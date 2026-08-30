/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Asynchronous logging subsystem
*
*  All producers (FTL threads, the web server, dnsmasq and the dnsmasq
*  TCP-query fork children) enqueue canonical log records into a lock-free
*  bounded ring in shared memory.  A single logger thread drains the ring and
*  performs every sink I/O: FTL.log, webserver.log, pihole.log, the in-memory
*  FIFO (API /logs), JSON stdout and the systemd journal.  This removes the
*  per-file mutexes and the pthread_atfork() dance that were needed when every
*  producer wrote directly.
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#include "FTL.h"
#include "version.h"
#include "daemon.h"
#include "args.h"
#include "logger.h"
#include "log.h"
#include "config/config.h"
#include "shmem.h"
#include "signals.h"

#include <stdatomic.h>
#include <fcntl.h>
#include <sched.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>

// journal_send(), journal_init(), journal_get_fd()
#ifdef HAVE_LIBJOURNAL
#include <journal.h>
#endif

// The FTL.h error-instrumented wrappers log on failure (log_warn -> enqueue),
// which recurses when the logger thread itself hits an error.  logger.c uses
// the raw libc calls instead; every sink write already carries its own
// fallback logic (syslog relay, dropping) below.
#undef free
#undef strdup
#undef calloc
#undef realloc
#undef printf
#undef fprintf
#undef vprintf
#undef vfprintf
#undef sprintf
#undef snprintf
#undef vsnprintf
#undef write
#undef strlen
#undef strnlen
#undef strncpy
#undef memset
#undef memcpy
#undef memmove
#undef strstr
#undef strcmp
#undef strncmp
#undef strcasecmp
#undef strncasecmp
#undef strcat
#undef strncat
#undef memcmp
#undef memmem

// The queue must work across a plain fork() (dnsmasq TCP children relay log
// records to the main process).  That requires the _Atomic operations on the
// counter/seq fields to be real instructions, not libc-internal locks.
//
// 64-bit counters cover i586+ (cmpxchg8b) and ARMv6K+ (ldrexd/strexd).  The
// original Raspberry Pi 1 is ARMv6 non-K (ARM1176JZF-S): no ldrexd/strexd, so
// ATOMIC_LLONG_LOCK_FREE is not 2 and 64-bit counters would fall back to
// libc/libatomic locks.  For that target use 32-bit counters instead: they
// ARE native LDREX/STREX instructions there, and the ring arithmetic is
// correct modulo 2^32 because the producer-consumer distance never exceeds
// LOGGER_RING_SLOTS << 2^32:
//   - "tail - head" computed in 32 bits equals the true distance whenever that
//     distance fits in 32 bits (it always does: the queue is bounded by
//     LOGGER_RING_SLOTS), and
//   - the per-slot seq markers only ever need to differ from the "consumed"
//     and "published" values of the same slot, which are separated by a power
//     of two (LOGGER_RING_SLOTS) and hence never collide modulo 2^32 - the
//     same invariant the 64-bit counters rely on, just without the safety
//     margin of an astronomically larger counter space.
#if ATOMIC_LLONG_LOCK_FREE == 2
typedef uint64_t log_ring_counter_t;
_Static_assert(ATOMIC_LLONG_LOCK_FREE == 2,
               "the log ring requires lock-free 64-bit atomics");
#else
typedef uint32_t log_ring_counter_t;
_Static_assert(ATOMIC_INT_LOCK_FREE == 2,
               "the log ring fallback needs lock-free 32-bit atomics");
#endif

// ---- Shared-memory ring ---------------------------------------------------
// Layout shared verbatim with dnsmasq TCP-query forks, which both produce and
// may consume records.  The structure is deliberately POD: no pointers, no
// padding surprises beyond normal alignment.

typedef struct {
	_Atomic log_ring_counter_t head;                // next counter value to consume
	_Atomic log_ring_counter_t tail;                // next counter value to claim
	_Atomic log_ring_counter_t seq[LOGGER_RING_SLOTS]; // per-slot generation markers
	struct log_record slot[LOGGER_RING_SLOTS];      // the records themselves
} logRing;

static logRing *ring = NULL;
static size_t ring_size = 0;
static char ring_name[64] = { 0 };                  // for shm_unlink()

// eventfd used to wake the logger thread
static int wake_fd = -1;

// ---- Thread state ----------------------------------------------------------
static pthread_t logger_thread;
static _Atomic bool thread_running = false;
static _Atomic bool stop_requested = false;

// Control requests posted by _FTL_log()-adjacent functions and consumed by the
// logger thread.  Posting is lock-free (plain atomics + eventfd write).
enum {
	CTRL_PATHS = 1u << 0,   // (re)target webserver/dnsmasq sinks (open_log_fds(false))
	CTRL_REOPEN = 1u << 1,  // reopen all sinks (SIGUSR2)
	CTRL_FLUSH = 1u << 2,   // drain, clear FIFO_DNSMASQ, truncate pihole.log
};
static _Atomic uint32_t logger_ctrl = 0;

// Flush completion handshake (logger_flush() -> logger thread -> reply)
static pthread_mutex_t flush_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t flush_cond = PTHREAD_COND_INITIALIZER;
static uint64_t flush_request_id = 0;
static uint64_t flush_done_id = 0;
static int flush_trunc_err = 0;

// ---- Sinks ------------------------------------------------------------------
#define LOGGER_MAX_PATH 4096

typedef struct {
	char path[LOGGER_MAX_PATH];  // owned by the logger thread
	int fd;                      // -1 when closed/unavailable
	dev_t dev;                   // identity of the file fd was opened on,
	ino_t ino;                   // for the stale-descriptor guard in sink_close()
} loggerSink;

static loggerSink sink_ftl = { .path = { 0 }, .fd = -1 };
static loggerSink sink_webserver = { .path = { 0 }, .fd = -1 };
static loggerSink sink_dnsmasq = { .path = { 0 }, .fd = -1 };

// Snapshot of the config-derived logging settings.  The logger thread never
// touches the live config (which the main thread may be parsing); it only
// reads this immutable-ish copy, guarded by snapshot_mutex.
typedef struct {
	enum log_destination dest;
	bool json_terminal;      // dest == LOG_DEST_JSON && !daemonmode
	char path_webserver[LOGGER_MAX_PATH];
	char path_dnsmasq[LOGGER_MAX_PATH];
	bool paths_valid;        // set once open_log_fds(false)/reconfigure ran
	bool hide_dnsmasq_warn;  // copied from config.misc.hide_dnsmasq_warn
#ifdef HAVE_LIBJOURNAL
	bool journal_available;  // dest == LOG_DEST_JOURNAL && journal connected
#endif
} loggerSnapshot;

static loggerSnapshot snapshot;
static pthread_mutex_t snapshot_mutex = PTHREAD_MUTEX_INITIALIZER;

#ifdef HAVE_LIBJOURNAL
static bool journal_ok = false;
#endif

// ---- Forward declarations ---------------------------------------------------
static void *logger_thread_main(void *arg);
static void logger_wake(void);
static void publish_sink_fds(void);

// ---- Ring queue (Vyukov bounded MPMC with per-slot seq markers) -------------
static bool log_ring_enqueue(struct log_record *rec, log_ring_counter_t *claimed)
{
	logRing *r = ring;
	if (r == NULL)
		return false;

	log_ring_counter_t tail = atomic_load_explicit(&r->tail, memory_order_relaxed);
	for (;;)
	{
		// The queue is full once the distance tail-head reaches the capacity.
		// head only ever increases, so a tail validated here can never be
		// written over a slot the consumer has not yet consumed.
		const log_ring_counter_t head = atomic_load_explicit(&r->head, memory_order_acquire);
		if (tail - head >= LOGGER_RING_SLOTS)
			return false;

		if (atomic_compare_exchange_weak_explicit(&r->tail, &tail, tail + 1,
		                                          memory_order_relaxed,
		                                          memory_order_relaxed))
			break;
		// tail was updated by the failed CAS; re-check capacity and retry
	}

	const log_ring_counter_t slot = tail % LOGGER_RING_SLOTS;
	r->slot[slot] = *rec;  // contains no pointers; plain POD copy
	// Publish with a release store: the consumer observes the record's data
	// (via the copying read) only after seeing this marker.
	atomic_store_explicit(&r->seq[slot], tail + 1, memory_order_release);
	*claimed = tail;
	return true;
}

static bool log_ring_pop(struct log_record *rec)
{
	logRing *r = ring;
	if (r == NULL)
		return false;

	log_ring_counter_t head = atomic_load_explicit(&r->head, memory_order_relaxed);
	for (;;)
	{
		const log_ring_counter_t tail = atomic_load_explicit(&r->tail, memory_order_acquire);
		if (head >= tail)
			return false;  // empty

		const log_ring_counter_t slot = head % LOGGER_RING_SLOTS;
		// Head-of-line slot not yet published: its producer is still copying
		// the record.  Report empty; the caller will retry shortly.  This lets
		// the consumer safely wait out out-of-order producers.
		if (atomic_load_explicit(&r->seq[slot], memory_order_acquire) != head + 1)
			return false;

		if (atomic_compare_exchange_weak_explicit(&r->head, &head, head + 1,
		                                          memory_order_acquire,
		                                          memory_order_relaxed))
			break;
		// head was updated by the failed CAS; re-check and retry
	}

	*rec = r->slot[head % LOGGER_RING_SLOTS];
	// Mark the slot consumed: the marker value now equals the counter a future
	// producer will claim for this slot, which the head-of-line check above
	// keeps distinct from the published (head+1) value.
	atomic_store_explicit(&r->seq[head % LOGGER_RING_SLOTS],
	                      head + LOGGER_RING_SLOTS, memory_order_release);
	return true;
}

static void logger_drain_eventfd(void)
{
	// Drain the eventfd counter so an already-satisfied wake-up does not make
	// the consumer spin through empty drains.
	uint64_t v;
	while (read(wake_fd, &v, sizeof(v)) > 0) { /* keep draining */ }
}

static void logger_wake(void)
{
	if (wake_fd < 0)
		return;
	const uint64_t one = 1;
	(void)!write(wake_fd, &one, sizeof(one));
}

static bool logger_ring_prepare(void)
{
	// The queue must survive the daemonize double-fork (the consumer thread
	// is respawned in the grandchild via logger_start_after_daemonize()), so
	// it is backed by a POSIX shared-memory object.  The PID in the name
	// isolates instances (and matches the /dev/shm/FTL-* cleanup pattern
	// used by the test suite).
	snprintf(ring_name, sizeof(ring_name), "/FTL-%d-logging", (int)getpid());

	int fd = shm_open(ring_name, O_RDWR | O_CREAT | O_EXCL, 0600);
	if (fd < 0 && errno == EEXIST)
	{
		// Stale object from a crashed incarnation holding the same PID
		shm_unlink(ring_name);
		fd = shm_open(ring_name, O_RDWR | O_CREAT | O_EXCL, 0600);
	}
	if (fd < 0)
		return false;

	ring_size = sizeof(logRing);
	if (ftruncate(fd, (off_t)ring_size) != 0)
	{
		close(fd);
		shm_unlink(ring_name);
		return false;
	}

	ring = mmap(NULL, ring_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	close(fd);
	if (ring == MAP_FAILED)
	{
		ring = NULL;
		shm_unlink(ring_name);
		return false;
	}

	return true;
}

static void logger_ring_teardown(void)
{
	if (ring != NULL)
	{
		munmap(ring, ring_size);
		ring = NULL;
	}
	if (ring_name[0] != '\0')
	{
		shm_unlink(ring_name);
		ring_name[0] = '\0';
	}
	if (wake_fd >= 0)
	{
		close(wake_fd);
		wake_fd = -1;
	}
}

// ---- Producer side ------------------------------------------------------------
void log_record_init(struct log_record *rec, const enum log_source source,
                     const int priority, const enum debug_flag flag)
{
	// Capture the production time with sub-second precision up front.  Every
	// sink renders this value, so the timestamps in the log files are the
	// exact production timestamps with millisecond precision - they are never
	// re-sampled when the logger thread drains the record.
	clock_gettime(CLOCK_REALTIME, &rec->ts);
	rec->priority = priority;
	rec->flag = flag;
	rec->source = source;
	rec->pid = getpid();
	rec->tid = gettid();
	// Classify the producing process NOW: main_pid() changes once the daemon
	// double-fork completes, and records produced before that (FTL startup
	// lines) must still be rendered as the main process, not as a fork.
	rec->is_fork = is_fork(main_pid(), rec->pid);
	rec->len = 0;
	rec->func[0] = '\0';
	rec->message[0] = '\0';
}

static bool try_enqueue(struct log_record *rec)
{
	// Backpressure policy: low-severity records are dropped immediately when
	// the queue is full, WARNING/ERROR after a bounded retry and CRIT/beyond
	// after a longer retry, so the daemon threads never block on logging.
	const unsigned int max_retries = rec->priority <= LOG_CRIT     ? 1000u :
	                                 rec->priority <= LOG_WARNING  ? 100u  : 0u;

	unsigned int retries = 0;
	log_ring_counter_t claimed;
	for (;;)
	{
		if (log_ring_enqueue(rec, &claimed))
		{
			// Wake the consumer only when OUR record made the previously
			// empty queue non-empty (head == claimed still holds).  If the
			// consumer is already draining past our slot it needs no wake;
			// records are drained in order and the poll timeout covers the
			// remaining boundary races.
			if (atomic_load_explicit(&ring->head, memory_order_acquire) == claimed)
				logger_wake();
			return true;
		}

		if (retries++ >= max_retries)
			return false;
		// Bounded spin instead of usleep: this may run inside a crash handler.
		sched_yield();
	}
}

bool log_ring_push(struct log_record *rec)
{
	// Queue not yet created (logger not started) or already torn down
	// (shutdown): fall back to syslog so the message is not lost entirely.
	// This mirrors the old behavior when no FTL.log was open.
	if (ring == NULL)
	{
		syslog(rec->priority, "%s", rec->message);
		return false;
	}

	return try_enqueue(rec);
}

// ---- Formatting helpers -------------------------------------------------------
// Replicate get_idstr()'s output from a record (the producer-side process/thread
// classification is preserved in rec->is_fork).
static void logger_get_idstr(char *idstr, const size_t size,
                             const struct log_record *rec)
{
	if(rec->pid == rec->tid)
	{
		if(rec->is_fork)
			snprintf(idstr, size, "%i/F%i", (int)rec->pid, (int)main_pid());
		else
			snprintf(idstr, size, "%iM", (int)rec->pid);
	}
	else
	{
		if(rec->is_fork)
			snprintf(idstr, size, "%i/F%i/T%i",
			         (int)rec->pid, (int)main_pid(), (int)rec->tid);
		else
			snprintf(idstr, size, "%i/T%i", (int)rec->pid, (int)rec->tid);
	}
}

static const char *logger_component(const enum log_source source)
{
	switch(source)
	{
		case LOG_SOURCE_FTL:       return "FTL";
		case LOG_SOURCE_DNSMASQ:   return "dnsmasq";
		case LOG_SOURCE_WEBSERVER: return "webserver";
	}
	return "FTL";
}

// Priority string for the file/FIFO/JSON sinks.  dnsmasq has no FTL debug
// flags, so its LOG_DEBUG is a plain "DEBUG" rather than the DEBUG_ANY
// catch-all priostr() maps to.  (Same as the previous FTL_dnsmasq_log().)
static const char *logger_prio(const struct log_record *rec)
{
	if(rec->source == LOG_SOURCE_DNSMASQ && rec->priority == LOG_DEBUG)
		return "DEBUG";
	return priostr(rec->priority, rec->flag);
}

// "YYYY-MM-DD HH:MM:SS.mmm TZ" in local time, byte-identical to the format
// the previous get_timestr(timestring, rec->ts, true, false) produced -
// except that the millisecond fraction is taken from the record's production
// time instead of being re-sampled at drain time.
static void logger_get_timestr_ms(char timestring[TIMESTR_SIZE],
                                  const struct timespec *ts)
{
	struct tm tm;
	localtime_r(&ts->tv_sec, &tm);

	const int millisec = (int)(ts->tv_nsec / 1000000);

	snprintf(timestring, TIMESTR_SIZE,
	         "%d-%02d-%02d %02d:%02d:%02d.%03i %s",
	         tm.tm_year + 1900,
	         tm.tm_mon + 1,
	         tm.tm_mday,
	         tm.tm_hour,
	         tm.tm_min,
	         tm.tm_sec,
	         millisec,
	         tm.tm_zone);

	// Ensure null termination
	timestring[TIMESTR_SIZE - 1] = '\0';
}

static void logger_get_timestr_iso8601(char timestring[TIMESTR_SIZE],
                                       const struct timespec *ts)
{
	struct tm tm;
	gmtime_r(&ts->tv_sec, &tm);

	// Millisecond precision from the record's production time (the previous
	// get_timestr_iso8601() only had the second-granular record time and
	// smuggled in the current millisecond when it happened to match)
	const int millisec = (int)(ts->tv_nsec / 1000000);

	snprintf(timestring, TIMESTR_SIZE,
	         "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
	         tm.tm_year + 1900,
	         tm.tm_mon + 1,
	         tm.tm_mday,
	         tm.tm_hour,
	         tm.tm_min,
	         tm.tm_sec,
	         millisec);

	// Ensure null termination
	timestring[TIMESTR_SIZE - 1] = '\0';
}

// Escape a string into a caller-supplied buffer for JSON output.  Never splits
// an escape sequence, so a short buffer truncates to valid JSON.
static void logger_json_escape(char *out, const size_t outlen, const char *in)
{
	static const char hex[] = "0123456789abcdef";
	size_t o = 0;

	for(const unsigned char *p = (const unsigned char *)in; *p != '\0'; p++)
	{
		char esc[6] = { '\\' };
		size_t len = 2;

		switch(*p)
		{
			case '"':  esc[1] = '"';  break;
			case '\\': esc[1] = '\\'; break;
			case '\b': esc[1] = 'b';  break;
			case '\f': esc[1] = 'f';  break;
			case '\n': esc[1] = 'n';  break;
			case '\r': esc[1] = 'r';  break;
			case '\t': esc[1] = 't';  break;

			default:
				if(*p >= 0x20)  // printable/UTF-8 pass through
				{
					esc[0] = (char)*p;
					len = 1;
					break;
				}

				esc[1] = 'u';
				esc[2] = '0';
				esc[3] = '0';
				esc[4] = hex[*p >> 4];
				esc[5] = hex[*p & 0x0f];
				len = 6;
				break;
		}

		if(o + len >= outlen)
			break;  // leave room for the NUL; escape sequence stays intact

		memcpy(out + o, esc, len);
		o += len;
	}

	out[o] = '\0';
}

// ---- Sink primitives ------------------------------------------------------------
static bool sink_write(loggerSink *sink, const char *buf, const size_t len)
{
	if(sink->fd < 0)
		return false;

	ssize_t written = 0;
	while(written < (ssize_t)len)
	{
		ssize_t rc = write(sink->fd, buf + written, len - (size_t)written);
		if(rc < 0)
		{
			if(errno == EINTR)
				continue;
			return false;
		}
		written += rc;
	}
	return true;
}

static void sink_close(loggerSink *sink)
{
	if(sink->fd < 0)
		return;

	// Stale-descriptor guard: across fork() (daemon mode) the pre-fork logger
	// thread may have been frozen between its sink_close() and the matching
	// reopen, leaving this process with a sink fd number that is no longer
	// occupied by the sink file.  Closing such a recycled descriptor here
	// would destroy whatever the number was reused for (e.g. a freshly bound
	// dnsmasq DNS listener socket) and silently kill that listener.  Only
	// close the descriptor when it still refers to the file opened for the
	// sink; otherwise just drop the stale number.
	struct stat st;
	if(fstat(sink->fd, &st) != 0 || st.st_dev != sink->dev || st.st_ino != sink->ino)
	{
		sink->fd = -1;
		return;
	}
	close(sink->fd);
	sink->fd = -1;
}

static void sink_store_path(loggerSink *sink, const char *path)
{
	if(path != NULL && path[0] != '\0')
	{
		snprintf(sink->path, sizeof(sink->path), "%s", path);
		// Bases for the {"...","..."} over wraps: also fix any trailing
		// newline that a malicious/corrupt path could smuggle in.
		for(size_t i = 0; sink->path[i] != '\0'; i++)
			if(sink->path[i] == '\n')
				sink->path[i] = '\0';
	}
	else
	{
		sink->path[0] = '\0';
	}
}

// Reopen one sink, warning appropriately on failure.  Rethrows failed opens so
// SIGUSR2 can revive a sink that failed initially (missing directory, EACCES).
static void sink_open(loggerSink *sink, const bool is_ftl)
{
	struct stat st;
	sink_close(sink);
	if(sink->path[0] == '\0')
		return;
	sink->fd = open(sink->path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC,
	                S_IRUSR | S_IWUSR | S_IRGRP);
	if(sink->fd < 0 && is_ftl)
	{
		// Same diagnostics as the previous open_log_fds(true), but on stderr
		// (stdout may carry JSON output) and via syslog:
		fprintf(stderr,
		        "ERROR: Opening of FTL log (%s) failed: %s\nUsing syslog instead!\n",
		        sink->path, strerror(errno));
		syslog(LOG_ERR, "Opening of FTL's log file failed, using syslog instead!");
		return;
	}

	// Remember the identity of the file we opened so sink_close() can detect
	// a descriptor that was recycled (see the guard there).
	if(fstat(sink->fd, &st) == 0)
	{
		sink->dev = st.st_dev;
		sink->ino = st.st_ino;
	}
}

// Write a bare FTL.log warning from the logger thread itself (bypassing the
// queue - we ARE the logger).  Failure to open web/pihole logs uses this so
// the "still relayed to the FTL log" guarantee holds even though the warning
// cannot be enqueued.
static void logger_write_direct_warning(loggerSink *sink, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));
static void logger_write_direct_warning(loggerSink *sink, const char *fmt, ...)
{
	char msg[LOGGER_MAX_MESSAGE];
	va_list args;
	va_start(args, fmt);
	vsnprintf(msg, sizeof(msg), fmt, args);
	va_end(args);

	// Build the idstr of the logger thread itself
	struct log_record me = { 0 };
	me.pid = getpid();
	me.tid = gettid();
	me.is_fork = is_fork(main_pid(), me.pid);
	char idstr[42];
	logger_get_idstr(idstr, sizeof(idstr), &me);

	char timestring[TIMESTR_SIZE];
	get_timestr(timestring, time(NULL), true, false);

	// Sized so the longest message (LOGGER_MAX_MESSAGE bytes) plus the
	// timestamp, idstr and fixed prefix can never be truncated
	char line[LOGGER_MAX_MESSAGE + 512];
	int off = snprintf(line, sizeof(line), "%s [%s] WARNING: %s",
	                   timestring, idstr, msg);
	if(off < 0 || off >= (int)sizeof(line))
		off = (int)sizeof(line) - 1;
	line[off++] = '\n';

	if(!sink_write(sink, line, (size_t)off))
		syslog(LOG_WARNING, "%s", msg);
}

// ---- Record rendering -----------------------------------------------------------
// Render one "TIMESTRING [idstr] PRIO: <message>\n" line (the FTL.log and
// webserver.log format) into the given sink.  Returns false when no write
// happened (fd missing or write error) so the caller can apply its fallback.
static bool logger_file_line(loggerSink *sink, const struct log_record *rec,
                             const char *prio)
{
	char timestring[TIMESTR_SIZE];
	logger_get_timestr_ms(timestring, &rec->ts);

	char idstr[42];
	logger_get_idstr(idstr, sizeof(idstr), rec);

	// Same 2048-byte line cap as the previous per-file writers
	char line[2048];
	int off = snprintf(line, sizeof(line), "%s [%s] %s: ",
	                   timestring, idstr, prio);
	if(off < 0 || off >= (int)sizeof(line))
		off = (int)sizeof(line) - 1;

	if(rec->len > 0)
	{
		const size_t space = sizeof(line) - (size_t)off - 1u;  // room for '\n'
		const size_t copy = rec->len < space ? rec->len : space;
		memcpy(line + off, rec->message, copy);
		off += (int)copy;
	}
	line[off++] = '\n';

	return sink_write(sink, line, (size_t)off);
}

// pihole.log, byte-identical to the previous FTL_write_dnsmasq_log()
static void logger_dnsmasq_line(struct log_record *rec)
{
	time_t now = rec->ts.tv_sec;
	char ctime_buf[26];
	const char *ctime_str = ctime_r(&now, ctime_buf);
	if(ctime_str == NULL)
		ctime_str = "Thu Jan  1 00:00:00 1970\n";
	char ts_buf[16];
	snprintf(ts_buf, sizeof(ts_buf), "%.15s", ctime_str + 4);

	char line[2048];
	int off = snprintf(line, sizeof(line), "%s dnsmasq%s[%d]: ",
	                   ts_buf, rec->func, (int)rec->pid);
	if(off < 0 || off >= (int)sizeof(line))
		off = (int)sizeof(line) - 1;

	if(rec->len > 0)
	{
		const size_t space = sizeof(line) - (size_t)off - 1u;
		const size_t copy = rec->len < space ? rec->len : space;
		memcpy(line + off, rec->message, copy);
		off += (int)copy;
	}
	line[off++] = '\n';

	if(!sink_write(&sink_dnsmasq, line, (size_t)off) && rec->priority <= LOG_WARNING)
		// pihole.log unavailable - keep warnings/errors durable via syslog
		syslog(rec->priority, "%s", rec->message);
}

static void logger_json_line(struct log_record *rec, const char *prio)
{
	char timestring_iso8601[TIMESTR_SIZE];
	logger_get_timestr_iso8601(timestring_iso8601, &rec->ts);

	char idstr[42];
	logger_get_idstr(idstr, sizeof(idstr), rec);

	// Escape into a temporary buffer; only the message needs escaping as the
	// other fields are controlled by the code
	char escaped_msg[8192];
	logger_json_escape(escaped_msg, sizeof(escaped_msg), rec->message);

	// Same framing as the previous write_json_log().  line is sized so that
	// any message that fits into escaped_msg can never exceed it (the escape
	// output is capped at 8191 bytes, the JSON overhead is well below 256).
	// The deliberately generous size also keeps -Wformat-truncation quiet
	// considering the widest possible field values the compiler models.
	char line[2 * sizeof(escaped_msg)];
	int off = snprintf(line, sizeof(line),
		"{\"timestamp\":\"%s\",\"log_level\":\"%s\",\"service\":\"pihole-FTL\","
		"\"component\":\"%s\",\"pid\":\"%s\",\"message\":\"%s\"}\n",
		timestring_iso8601, prio, logger_component(rec->source),
		idstr, escaped_msg);

	if(off < 0 || off >= (int)sizeof(line))
		off = (int)sizeof(line) - 1;

	// Use write() to avoid stdio buffering.  stdout is O_NONBLOCK in JSON
	// mode, so a full/stalled pipe drops lines instead of stalling FTL.
	(void)!write(STDOUT_FILENO, line, (size_t)off);
}

#ifdef HAVE_LIBJOURNAL
static void logger_journal_line(struct log_record *rec)
{
	// Same fields as the previous _FTL_log()/_log_web()/FTL_dnsmasq_log()
	// journal_send() calls.  dnsmasq records historically omit DEBUG_FLAG.
	const char *component = logger_component(rec->source);
	if(rec->source == LOG_SOURCE_DNSMASQ)
		journal_send("MESSAGE=%s", rec->message,
		             "PRIORITY=%d", rec->priority,
		             "COMPONENT=%s", component,
		             "SYSLOG_IDENTIFIER=pihole-FTL",
		             "TID=%d", rec->tid,
		             NULL);
	else
		journal_send("MESSAGE=%s", rec->message,
		             "PRIORITY=%d", rec->priority,
		             "DEBUG_FLAG=%s", debugstr(rec->flag),
		             "COMPONENT=%s", component,
		             "SYSLOG_IDENTIFIER=pihole-FTL",
		             "TID=%d", rec->tid,
		             NULL);
}
#endif

// ---- Dispatch -----------------------------------------------------------------
// Relay a record into the SHM FIFO.  This thread is the sole FIFO writer
// (every producer goes through the ring), so no lock is taken here: locking
// would let the thread re-enter a mutex it already holds whenever a lock- or
// timing-debug line produced below loops back through the queue.
static void logger_fifo(struct log_record *rec, const char *prio)
{
	size_t flen = rec->len + 1u;  // include zero-terminator
	if(flen > MAX_MSG_FIFO)
		flen = MAX_MSG_FIFO;

	enum fifo_logs which = FIFO_FTL;
	switch(rec->source)
	{
		case LOG_SOURCE_FTL:       which = FIFO_FTL;       break;
		case LOG_SOURCE_DNSMASQ:   which = FIFO_DNSMASQ;   break;
		case LOG_SOURCE_WEBSERVER: which = FIFO_WEBSERVER; break;
	}

	// Store the record's production timestamp (double epoch seconds, the
	// same representation double_time() produced in the synchronous logger)
	const double ts = (double)rec->ts.tv_sec + 1e-9 * (double)rec->ts.tv_nsec;
	add_to_fifo_buffer(which, rec->message, prio, flen, ts);
}

static void logger_dispatch(struct log_record *rec)
{
	const char *prio = logger_prio(rec);

	// The FIFO relay happens for every record regardless of destination,
	// matching the previous behavior.
	logger_fifo(rec, prio);

	// Read the current destination settings (configured by the main thread)
	pthread_mutex_lock(&snapshot_mutex);
	const enum log_destination dest = snapshot.dest;
	const bool json_terminal = snapshot.json_terminal;
#ifdef HAVE_LIBJOURNAL
	const bool journal = snapshot.journal_available;
#endif
	pthread_mutex_unlock(&snapshot_mutex);

	if(json_terminal)
		logger_json_line(rec, prio);

#ifdef HAVE_LIBJOURNAL
	if(journal)
		logger_journal_line(rec);
#endif

	if(dest != LOG_DEST_FILE)
		return;

	switch(rec->source)
	{
		case LOG_SOURCE_FTL:
			if(!logger_file_line(&sink_ftl, rec, prio))
				// No FTL.log available - fall back to syslog
				syslog(rec->priority, "%s", rec->message);
			break;
		case LOG_SOURCE_WEBSERVER:
			// webserver.log unavailable: keep severe messages durable in
			// FTL.log (previous behavior, minus the duplicate FIFO entry)
			if(!logger_file_line(&sink_webserver, rec, prio) &&
			   rec->priority <= LOG_WARNING)
			{
				if(!logger_file_line(&sink_ftl, rec, prio))
					syslog(rec->priority, "%s", rec->message);
			}
			break;
		case LOG_SOURCE_DNSMASQ:
			logger_dnsmasq_line(rec);
			break;
	}
}

static void logger_drain(void)
{
	struct log_record rec;
	while(log_ring_pop(&rec))
		logger_dispatch(&rec);
}

// ---- Flush ------------------------------------------------------------------
static void logger_do_flush(void)
{
	// Drain everything enqueued so far, then clear the in-memory dnsmasq FIFO
	// and truncate pihole.log so an API flush empties exactly the records
	// produced before the request was posted.
	logger_drain();

	int trunc_err = 0;
	// Clear the dnsmasq FIFO.  Same single-writer argument as logger_fifo():
	// no other thread appends to the FIFO, so no lock is required.
	if(fifo_log)
		memset(&fifo_log->logs[FIFO_DNSMASQ], 0,
		       sizeof(fifo_log->logs[FIFO_DNSMASQ]));

	if(sink_dnsmasq.fd < 0)
		trunc_err = -1;                              // no log file open
	else if(ftruncate(sink_dnsmasq.fd, 0) != 0)
		trunc_err = errno;                           // fd stays usable for appending

	// Signal completion to the waiting API thread
	pthread_mutex_lock(&flush_mutex);
	flush_done_id = flush_request_id;
	flush_trunc_err = trunc_err;
	pthread_cond_broadcast(&flush_cond);
	pthread_mutex_unlock(&flush_mutex);
}

// ---- Sink (re)configuration -----------------------------------------------------
static void logger_reopen_all(void)
{
	sink_open(&sink_ftl, true);
	sink_open(&sink_webserver, false);
	sink_open(&sink_dnsmasq, false);
	publish_sink_fds();
}

// Apply open_log_fds(false): (re)target webserver.log and pihole.log from the
// config snapshot.  The FTL sink keeps whatever fd it had - exactly what the
// previous code did (FTL.log was only ever opened during init).
static void logger_update_paths(void)
{
	pthread_mutex_lock(&snapshot_mutex);
	char webserver_path[LOGGER_MAX_PATH];
	char dnsmasq_path[LOGGER_MAX_PATH];
	const bool hide_dnsmasq_warn = snapshot.hide_dnsmasq_warn;
	snprintf(webserver_path, sizeof(webserver_path), "%s", snapshot.path_webserver);
	snprintf(dnsmasq_path, sizeof(dnsmasq_path), "%s", snapshot.path_dnsmasq);
	pthread_mutex_unlock(&snapshot_mutex);

	sink_store_path(&sink_webserver, webserver_path);
	sink_store_path(&sink_dnsmasq, dnsmasq_path);
	sink_open(&sink_webserver, false);
	sink_open(&sink_dnsmasq, false);

	// Emit the "unavailable" warnings via the normal path (mirroring the old
	// log_warn()) now that the sinks are (re)opened
	if(sink_webserver.fd < 0 && webserver_path[0] != '\0')
		logger_write_direct_warning(&sink_ftl,
			"webserver.log is unavailable (%s); warnings are still relayed to the FTL log",
			strerror(errno));
	if(sink_dnsmasq.fd < 0 && dnsmasq_path[0] != '\0')
	{
		if(hide_dnsmasq_warn)
			logger_write_direct_warning(&sink_ftl,
				"pihole.log is unavailable (%s); dnsmasq warnings are hidden (misc.hide_dnsmasq_warn)",
				strerror(errno));
		else
			logger_write_direct_warning(&sink_ftl,
				"pihole.log is unavailable (%s); dnsmasq warnings are still relayed to the FTL log",
				strerror(errno));
	}
}

static void logger_process_controls(void)
{
	const uint32_t ctrl = atomic_exchange_explicit(&logger_ctrl, 0,
	                                                memory_order_acq_rel);
	if(ctrl == 0)
		return;

	// A pending flush must always be answered - an API thread may be blocked
	// in logger_flush() waiting for the completion handshake, even while the
	// logger is shutting down.
	if(ctrl & CTRL_FLUSH)
		logger_do_flush();

	// Path changes and sink reopens are pointless once the thread is stopping
	if(stop_requested)
		return;

	if(ctrl & CTRL_PATHS)
		logger_update_paths();
	if(ctrl & CTRL_REOPEN)
		logger_reopen_all();
}

// ---- The logger thread ------------------------------------------------------------
static void *logger_thread_main(void *arg)
{
	(void)arg;

	logger_reopen_all();

	atomic_store_explicit(&thread_running, true, memory_order_release);

	// JSON output uses stdout; make it non-blocking so a stalled consumer
	// pipe drops lines instead of stalling the logger (and thus all sinks).
	if(snapshot.json_terminal)
	{
		const int flags = fcntl(STDOUT_FILENO, F_GETFL, 0);
		if(flags >= 0)
			(void)fcntl(STDOUT_FILENO, F_SETFL, flags | O_NONBLOCK);
	}

	for(;;)
	{
		// Drain the whole batch that made the queue non-empty
		logger_drain();

		// Apply control requests after the drain: a flush must see the queue
		// empty, a reopen must not race a write.
		logger_process_controls();

		if(atomic_load_explicit(&stop_requested, memory_order_acquire))
			break;

		// Nothing drained and no control pending: wait for a producer.  The
		// timeout covers fork children, which must not write the eventfd.
		const uint32_t ctrl = atomic_load_explicit(&logger_ctrl, memory_order_relaxed);
		if(ctrl == 0)
		{
			struct pollfd pfd = { .fd = wake_fd, .events = POLLIN };
			const int pollrc = poll(&pfd, 1, LOGGER_POLL_TIMEOUT_MS);
			if(pollrc > 0)
				logger_drain_eventfd();
		}
	}

	// Final drain so shutdown never loses the records that raced the stop
	// request, then process any final controls (e.g. a pending flush).
	logger_drain();
	logger_process_controls();

	return NULL;
}

// ---- Public control API -----------------------------------------------------------
static void logger_take_snapshot(void)
{
	// Main thread only - the logger thread must never read the live config.
	// This runs before any dnsmasq fork and while the logger thread either
	// does not exist yet or is only reading the previous snapshot copy.
	pthread_mutex_lock(&snapshot_mutex);
	snapshot.dest = config.files.log.destination.v.log_destination;
	snapshot.json_terminal = (snapshot.dest == LOG_DEST_JSON) && !daemonmode;
	snapshot.hide_dnsmasq_warn = config.misc.hide_dnsmasq_warn.v.b;
#ifdef HAVE_LIBJOURNAL
	snapshot.journal_available = (snapshot.dest == LOG_DEST_JOURNAL) && journal_ok;
#endif
	if(config.files.log.webserver.v.s != NULL)
		snprintf(snapshot.path_webserver, sizeof(snapshot.path_webserver), "%s",
		         config.files.log.webserver.v.s);
	else
		snapshot.path_webserver[0] = '\0';
	if(config.files.log.dnsmasq.v.s != NULL)
		snprintf(snapshot.path_dnsmasq, sizeof(snapshot.path_dnsmasq), "%s",
		         config.files.log.dnsmasq.v.s);
	else
		snapshot.path_dnsmasq[0] = '\0';
	snapshot.paths_valid = true;
	pthread_mutex_unlock(&snapshot_mutex);
}

bool logger_start(void)
{
	// The ring + eventfd are never torn down by logger_stop(), so starting
	// again after a stop only needs a fresh thread.
	if(atomic_load_explicit(&thread_running, memory_order_acquire))
		return true;

	if(ring == NULL && !logger_ring_prepare())
	{
		syslog(LOG_ERR, "Cannot create log queue in shared memory: %s",
		       strerror(errno));
		return false;
	}

	if(wake_fd < 0)
		wake_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if(wake_fd < 0)
	{
		syslog(LOG_ERR, "Cannot create log wakeup eventfd: %s", strerror(errno));
		return false;
	}

	// Ignore SIGPIPE so stdout JSON writes to a closed pipe cannot kill FTL;
	// civetweb already did this for its own sockets
	signal(SIGPIPE, SIG_IGN);

#ifdef HAVE_LIBJOURNAL
	// Establish the journal connection synchronously (from the main thread,
	// pre-fork) so a connect failure exits with the same console error as
	// before.  Do this before the snapshot so journal_available is current.
	if(!journal_ok && config.files.log.destination.v.log_destination == LOG_DEST_JOURNAL)
	{
		const int rc = journal_init();
		if(rc < 0)
		{
			fprintf(stderr,
			        "pihole-FTL: Cannot connect to systemd-journald: %s\n",
			        strerror(-rc));
			exit(EXIT_FAILURE);
		}
		journal_ok = true;
	}
#endif

	logger_take_snapshot();

	// Seed the FTL sink path.  On the first start this mirrors the old
	// open_log_fds(true) which only knew about FTL.log (configured via
	// getLogFilePath()); webserver.log/pihole.log paths arrive later through
	// logger_reconfigure().
	if(config.files.log.ftl.v.s != NULL)
		sink_store_path(&sink_ftl, config.files.log.ftl.v.s);

	if(pthread_create(&logger_thread, NULL, logger_thread_main, NULL) != 0)
	{
		syslog(LOG_ERR, "Cannot create logger thread: %s", strerror(errno));
		return false;
	}

	// Wait (bounded) for the logger thread to open its sinks so that
	// subsequent code (dnsmasq close_fds) sees the published fds.
	for(unsigned int i = 0; i < 10000u &&
	    !atomic_load_explicit(&thread_running, memory_order_acquire); i++)
		sched_yield();

	return true;
}

void logger_stop(void)
{
	if(!atomic_load_explicit(&thread_running, memory_order_acquire))
		return;

	atomic_store_explicit(&stop_requested, true, memory_order_release);
	logger_wake();
	pthread_join(logger_thread, NULL);
	atomic_store_explicit(&thread_running, false, memory_order_relaxed);
	atomic_store_explicit(&stop_requested, false, memory_order_relaxed);

	// The thread closed its sinks on exit; the ring + eventfd stay alive
	// across a stop/start cycle (e.g. during shutdown the main thread may
	// still want to route records while the queue is drained).
}

void logger_shutdown(void)
{
	// Drain the queue even if the thread is gone (only possible when nothing
	// was ever logged).  Normally: post stop, drain whatever the thread left.
	if(atomic_load_explicit(&thread_running, memory_order_acquire))
		logger_stop();

	// Belt-and-suspenders: after the thread has joined, retry the remaining
	// records from this (the only) remaining thread before destroying the
	// queue.  Records the main thread produced while shutting down after the
	// logger was stopped (banner, destroy_shmem() debug output, ...) are
	// drained here.  The FIFO relay inside logger_dispatch() is a no-op in
	// this window because destroy_shmem() already cleared fifo_log.
	struct log_record leftover;
	while(log_ring_pop(&leftover))
		logger_dispatch(&leftover);

	logger_ring_teardown();
}

void logger_start_after_daemonize(void)
{
	// fork() keeps only the calling thread: the pre-fork logger thread does
	// not exist in this (double-forked) process, and it is gone forever —
	// the parent process (and with it that thread and its copies of the
	// state flags) has already exited.  The ring and the wakeup eventfd were
	// inherited untouched, so the leftover records are still waiting for a
	// consumer.  The stale copy of the state flags would make logger_start()
	// believe the old thread is still running, so force them to "not running"
	// before respawning the consumer in this process.
	atomic_store_explicit(&stop_requested, false, memory_order_relaxed);
	atomic_store_explicit(&thread_running, false, memory_order_relaxed);
	logger_start();
}

void logger_reconfigure(void)
{
	logger_take_snapshot();
	atomic_fetch_or_explicit(&logger_ctrl, CTRL_PATHS, memory_order_release);
	logger_wake();
}

int logger_flush(void)
{
	pthread_mutex_lock(&flush_mutex);

	// Request + wait, generating a new request id so concurrent calls each
	// wait for their own completion.
	flush_request_id++;
	const uint64_t my_request = flush_request_id;
	atomic_fetch_or_explicit(&logger_ctrl, CTRL_FLUSH, memory_order_release);
	logger_wake();

	while(flush_done_id < my_request)
		pthread_cond_wait(&flush_cond, &flush_mutex);

	const int trunc_err = flush_trunc_err;
	pthread_mutex_unlock(&flush_mutex);
	return trunc_err;
}

void logger_sig_reopen(void)
{
	// Async-signal-safe: only touches an atomic and writes the eventfd
	atomic_fetch_or_explicit(&logger_ctrl, CTRL_REOPEN, memory_order_release);
	if(wake_fd >= 0)
	{
		const uint64_t one = 1;
		(void)!write(wake_fd, &one, sizeof(one));
	}
}

// ---- fd publication (dnsmasq close_fds()) --------------------------------------
// Published as a fixed-size atomic array of LOGGER_MAX_SINK_FDS entries: the
// three log files, the eventfd and (in journal mode) the journald socket.
#define LOGGER_MAX_SINK_FDS 5
static _Atomic int logger_fds[LOGGER_MAX_SINK_FDS];

static void publish_sink_fds(void)
{
	int fds[LOGGER_MAX_SINK_FDS] = {
		sink_ftl.fd,
		sink_webserver.fd,
		sink_dnsmasq.fd,
		wake_fd,
		-1,
	};
#ifdef HAVE_LIBJOURNAL
	if(journal_ok)
		fds[4] = journal_get_fd();
#endif
	for(int i = 0; i < LOGGER_MAX_SINK_FDS; i++)
		atomic_store_explicit(&logger_fds[i], fds[i], memory_order_release);
}

int __attribute__((pure)) is_log_fd(const int fd)
{
	if(fd < 0)
		return false;

	// The array starts out full of 0, but dnsmasq close_fds() only runs after
	// the logger thread has published (logger_reopen_all() -> publish).
	for(int i = 0; i < LOGGER_MAX_SINK_FDS; i++)
		if(atomic_load_explicit(&logger_fds[i], memory_order_acquire) == fd)
			return true;
	return false;
}