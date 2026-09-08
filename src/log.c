/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Logging routines
*
*  Since the asynchronous logging rewrite (logger.c) this file only contains
*  the producer side: formatting log records and passing them to the shared
*  logger thread.  All sink I/O (FTL.log, webserver.log, pihole.log, FIFO,
*  JSON, journal) happens in the logger thread.
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "version.h"
// is_fork()
#include "daemon.h"
#include "config/config.h"
#include "log.h"
#include "logger.h"
// global variable username
#include "main.h"
// global variable daemonmode
#include "args.h"
// global counters variable
#include "shmem.h"
// main_pid()
#include "signals.h"
// logg_fatal_dnsmasq_message()
#include "database/message-table.h"
// delete_old_queries_from_db()
#include "database/query-table.h"
// runGC()
#include "gc.h"

#include <stdatomic.h>

static bool print_log = true, print_stdout = true;
bool debug_flags[DEBUG_MAX] = { false };

// Cached logging destination for the producers (avoid touching the live
// config, which may be mid-parse while other threads log).  It is captured at
// startup and never changes afterwards (files.log.destination is read-only).
static _Atomic enum log_destination cached_dest = LOG_DEST_FILE;

void clear_debug_flags(void)
{
	for(unsigned int i = 0; i < DEBUG_MAX; i++)
		debug_flags[i] = false;
}

void log_ctrl(bool plog, bool pstdout)
{
	print_log = plog;
	print_stdout = pstdout;
}

// Start/stop the asynchronous logger.  open_log_fds(true) is the early call
// (only FTL.log / JSON / journal is active); open_log_fds(false) is the late
// call once webserver.log and pihole.log paths are known from the config.
void open_log_fds(bool early)
{
	if(early)
	{
		atomic_store_explicit(&cached_dest,
		                      config.files.log.destination.v.log_destination,
		                      memory_order_relaxed);
		(void)logger_start();
	}
	else
	{
		atomic_store_explicit(&cached_dest,
		                      config.files.log.destination.v.log_destination,
		                      memory_order_relaxed);
		logger_reconfigure();
	}
}

// Signal that log fds need to be reopened (called from SIGUSR2 handler path).
// Async-signal-safe: forwarding this to the logger thread.
void mark_log_reopen(void)
{
	logger_sig_reopen();
}

// Return time(NULL) but with (up to) nanosecond accuracy
// The resolution of clock depends on the hardware implementation and cannot be
// changed by a particular process
double double_time(void)
{
	struct timespec tp;
	// POSIX.1-2008: "Applications should use the clock_gettime() function instead
	// of the obsolescent gettimeofday() function"
	clock_gettime(CLOCK_REALTIME, &tp);
	return tp.tv_sec + 1e-9*tp.tv_nsec;
}

// Get a human-readable time string
// timein is a double epoch-seconds timestamp as produced by double_time() so
// that the millisecond fraction comes from the timestamp itself
void get_timestr(char timestring[TIMESTR_SIZE], const double timein, const bool millis, const bool uri_compatible)
{
	const time_t seconds = (time_t)timein;
	struct tm tm;
	localtime_r(&seconds, &tm);
	char space = ' ';
	char colon = ':';
	if(uri_compatible)
	{
		space = '_';
		colon = '-';
	}

	if(millis)
	{
		const int millisec = (int)((timein - seconds) * 1000.0);

		snprintf(timestring, TIMESTR_SIZE, "%d-%02d-%02d%c%02d%c%02d%c%02d.%03i%c%s",
		        tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, space,
		        tm.tm_hour, colon, tm.tm_min, colon, tm.tm_sec, millisec, space, tm.tm_zone);
	}
	else
	{
		snprintf(timestring, TIMESTR_SIZE, "%d-%02d-%02d%c%02d%c%02d%c%02d%c%s",
		        tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, space,
		        tm.tm_hour, colon, tm.tm_min, colon, tm.tm_sec, space, tm.tm_zone);
	}

	// Ensure that the string is zero-terminated
	timestring[TIMESTR_SIZE - 1] = '\0';
}

// Return the current year
unsigned int get_year(const time_t timein)
{
	struct tm tm;
	localtime_r(&timein, &tm);
	return tm.tm_year + 1900;
}

bool __attribute__((pure)) FTL_want_stdout(void)
{
	return !daemonmode && config.files.log.destination.v.log_destination != LOG_DEST_JSON;
}

// ID string of the calling process/thread, e.g. "12345M" (main process),
// "12345T2" (a thread of the main process) or "12345/F5678" (a fork child).
// Used for the human-readable terminal output; the file sinks derive the same
// string from the log record (see logger_get_idstr() in logger.c).
void get_idstr(char *idstr, size_t size)
{
	const int pid = getpid(); // Get the process ID of the calling process
	const int mpid = main_pid(); // Get the process ID of the main FTL process
	const int tid = gettid(); // Get the thread ID of the calling process

	// There are four cases we have to differentiate here:
	if(pid == tid)
		if(is_fork(mpid, pid))
			// Fork of the main process
			snprintf(idstr, size, "%i/F%i", pid, mpid);
		else
			// Main process
			snprintf(idstr, size, "%iM", pid);
	else
		if(is_fork(mpid, pid))
			// Thread of a fork of the main process
			snprintf(idstr, size, "%i/F%i/T%i", pid, mpid, tid);
		else
			// Thread of the main process
			snprintf(idstr, size, "%i/T%i", pid, tid);
}

const char * __attribute__((const)) priostr(const int priority, const enum debug_flag flag)
{
	switch (priority)
	{
		// system is unusable
		case LOG_EMERG:
			return "EMERG";
		// action must be taken immediately
		case LOG_ALERT:
			return "ALERT";
		// critical conditions
		case LOG_CRIT:
			return "CRIT";
		// error conditions
		case LOG_ERR:
			return "ERROR";
		// warning conditions
		case LOG_WARNING:
			return "WARNING";
		// normal but significant condition
		case LOG_NOTICE:
			return "NOTICE";
		// informational
		case LOG_INFO:
			return "INFO";
		// debug-level messages
		case LOG_DEBUG:
			return debugstr(flag);
		// invalid option
		default:
			return "UNKNOWN";
	}
}

const char *debugstr(const enum debug_flag flag)
{
	switch (flag)
	{
		case DEBUG_DATABASE:
			return "DEBUG_DATABASE";
		case DEBUG_NETWORKING:
			return "DEBUG_NETWORKING";
		case DEBUG_LOCKS:
			return "DEBUG_LOCKS";
		case DEBUG_QUERIES:
			return "DEBUG_QUERIES";
		case DEBUG_FLAGS:
			return "DEBUG_FLAGS";
		case DEBUG_SHMEM:
			return "DEBUG_SHMEM";
		case DEBUG_GC:
			return "DEBUG_GC";
		case DEBUG_ARP:
			return "DEBUG_ARP";
		case DEBUG_REGEX:
			return "DEBUG_REGEX";
		case DEBUG_API:
			return "DEBUG_API";
		case DEBUG_TLS:
			return "DEBUG_TLS";
		case DEBUG_OVERTIME:
			return "DEBUG_OVERTIME";
		case DEBUG_STATUS:
			return "DEBUG_STATUS";
		case DEBUG_CAPS:
			return "DEBUG_CAPS";
		case DEBUG_DNSSEC:
			return "DEBUG_DNSSEC";
		case DEBUG_VECTORS:
			return "DEBUG_VECTORS";
		case DEBUG_RESOLVER:
			return "DEBUG_RESOLVER";
		case DEBUG_EDNS0:
			return "DEBUG_EDNS0";
		case DEBUG_CLIENTS:
			return "DEBUG_CLIENTS";
		case DEBUG_ALIASCLIENTS:
			return "DEBUG_ALIASCLIENTS";
		case DEBUG_EVENTS:
			return "DEBUG_EVENTS";
		case DEBUG_HELPER:
			return "DEBUG_HELPER";
		case DEBUG_EXTRA:
			return "DEBUG_EXTRA";
		case DEBUG_CONFIG:
			return "DEBUG_CONFIG";
		case DEBUG_INOTIFY:
			return "DEBUG_INOTIFY";
		case DEBUG_WEBSERVER:
			return "DEBUG_WEBSERVER";
		case DEBUG_RESERVED:
			return "DEBUG_RESERVED";
		case DEBUG_NTP:
			return "DEBUG_NTP";
		case DEBUG_NETLINK:
			return "DEBUG_NETLINK";
		case DEBUG_TIMING:
			return "DEBUG_TIMING";
		case DEBUG_PERFORMANCE:
			return "DEBUG_PERFORMANCE";
		case DEBUG_DOTDOH:
			return "DEBUG_DOTDOH";
		case DEBUG_MAX:
			return "DEBUG_MAX";
		case DEBUG_NONE: // fall through
		default:
			return "DEBUG_ANY";
	}
}

// Format a log message into a record and enqueue it.  The logger thread takes
// care of the actual sinks; the drops (queue temporarily full) are counted by
// the logger.  This function never blocks.
static void log_record_format_and_push(struct log_record *rec, const char *format, va_list args)
	__attribute__((format(printf, 2, 0)));
static void log_record_format_and_push(struct log_record *rec, const char *format, va_list args)
{
	rec->len = vsnprintf(rec->message, sizeof(rec->message), format, args);

	// vsnprintf returns the would-be length, so clamp it to the buffer
	if(rec->len > sizeof(rec->message) - 1u)
		rec->len = sizeof(rec->message) - 1u;

	log_ring_push(rec);
}

void __attribute__ ((format (printf, 3, 4))) _FTL_log(const int priority, const enum debug_flag flag, const char *format, ...)
{
	// We have been explicitly asked to not print anything to the log
	if(!print_log && !print_stdout)
		return;

	va_list args;
	va_start(args, format);

	// Print to stdout (human-readable) unless structured logging is active
	// (JSON or journal).  This stays synchronous like before.
	const enum log_destination dest = atomic_load_explicit(&cached_dest,
	                                                       memory_order_relaxed);
	if((!daemonmode || cli_mode) && print_stdout &&
	   dest != LOG_DEST_JSON
#ifdef HAVE_LIBJOURNAL
	   && dest != LOG_DEST_JOURNAL
#endif
	   )
	{
		char timestring[TIMESTR_SIZE];
		get_timestr(timestring, time(NULL), true, false);

		char idstr[42];
		get_idstr(idstr, sizeof(idstr));
		const char *prio = priostr(priority, flag);

		// Only print time/ID string when not in direct user interaction (CLI mode)
		if(!cli_mode)
			printf("%s [%s] %s: ", timestring, idstr, prio);
		vprintf(format, args);
		printf("\n");
	}

	if(print_log)
	{
		// Enqueue a record for the logger thread
		struct log_record rec;
		log_record_init(&rec, LOG_SOURCE_FTL, priority, flag);
		log_record_format_and_push(&rec, format, args);
	}

	va_end(args);
}

void __attribute__ ((format (printf, 3, 4))) _log_web(const int priority, const enum debug_flag flag, const char *format, ...)
{
	// We have been explicitly asked to not print anything to the log
	if(!print_log && !print_stdout)
		return;

	va_list args;
	va_start(args, format);

	const enum log_destination dest = atomic_load_explicit(&cached_dest,
	                                                       memory_order_relaxed);
	// Print to stdout (human-readable) unless structured logging is active
	if((!daemonmode || cli_mode) && print_stdout &&
	   dest != LOG_DEST_JSON
#ifdef HAVE_LIBJOURNAL
	   && dest != LOG_DEST_JOURNAL
#endif
	   )
	{
		char timestring[TIMESTR_SIZE];
		get_timestr(timestring, time(NULL), true, false);

		char idstr[42];
		get_idstr(idstr, sizeof(idstr));
		const char *prio = priostr(priority, flag);

		// Only print time/ID string when not in direct user interaction (CLI mode)
		if(!cli_mode)
			printf("%s [%s] %s: ", timestring, idstr, prio);
		vprintf(format, args);
		printf("\n");
	}

	if(print_log)
	{
		// Enqueue a record for the logger thread
		struct log_record rec;
		log_record_init(&rec, LOG_SOURCE_WEBSERVER, priority, flag);
		log_record_format_and_push(&rec, format, args);
	}

	va_end(args);
}

// Log helper activity (may be script or lua)
void FTL_log_helper(const unsigned int n, ...)
{
	// Only log helper debug messages if enabled
	if(!(config.debug.helper.v.b))
		return;

	// Extract all variable arguments
	va_list args;
	char **arg = calloc(n, sizeof(char*));
	va_start(args, n);
	for(unsigned int i = 0; i < n; i++)
	{
		char *argin = va_arg(args, char*);
		if(argin == NULL)
			arg[i] = NULL;
		else
			arg[i] = argin;
	}

	// Select appropriate logging format
	switch (n)
	{
		case 1:
			log_debug(DEBUG_HELPER, "Script: Starting helper for action \"%s\"", arg[0]);
			break;
		case 2:
			log_debug(DEBUG_HELPER, "Script: FAILED to execute \"%s\": %s", arg[0], arg[1]);
			break;
		case 5:
			log_debug(DEBUG_HELPER, "Script: Executing \"%s\" with arguments: \"%s %s %s %s\"",
			          arg[0], arg[1], arg[2], arg[3], arg[4]);
			break;
		default:
			log_debug(DEBUG_HELPER, "ERROR: Unsupported number of arguments passed to FTL_log_helper(): %u", n);
			break;
	}
	va_end(args);
	free(arg);
}

void format_memory_size(char prefix[2], const off_t bytes, double * const formatted)
{
	unsigned int i;
	*formatted = bytes;
	// Determine exponent for human-readable display
	const char prefixes[] = { '\0', 'k', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y', 'R', '?' };
	for(i = 0; i < sizeof(prefixes)/sizeof(*prefixes) - 1; i++)
	{
		if(*formatted <= 1024.0)
			break;
		*formatted /= 1024.0;
	}
	// Chose matching SI prefix
	prefix[0] = prefixes[i];
	prefix[1] = '\0';
}

// Human-readable time
void format_time(char buffer[42], unsigned long seconds, double milliseconds)
{
	unsigned long umilliseconds = 0;
	if(milliseconds > 0)
	{
		seconds = milliseconds / 1000;
		umilliseconds = (unsigned long)milliseconds % 1000;
	}
	const unsigned int days = seconds / (60 * 60 * 24);
	seconds -= days * (60 * 60 * 24);
	const unsigned int hours = seconds / (60 * 60);
	seconds -= hours * (60 * 60);
	const unsigned int minutes = seconds / 60;
	seconds %= 60;

	buffer[0] = ' ';
	buffer[1] = '\0';
	if(days > 0)
		sprintf(buffer + strlen(buffer), "%ud ", days);
	if(hours > 0)
		sprintf(buffer + strlen(buffer), "%uh ", hours);
	if(minutes > 0)
		sprintf(buffer + strlen(buffer), "%um ", minutes);
	if(seconds > 0)
		sprintf(buffer + strlen(buffer), "%lus ", seconds);

	// Only append milliseconds when the timer value is less than 10 seconds
	if((days + hours + minutes) == 0 && seconds < 10 && umilliseconds > 0)
		sprintf(buffer + strlen(buffer), "%lums ", umilliseconds);
}

// Store fatal dnsmasq errors for further processing (this is called from dnsmasq code)
void FTL_log_dnsmasq_fatal(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	char buffer[MAX_MSG_FIFO];
	vsnprintf(buffer, sizeof(buffer), format, args);
	va_end(args);

	// Store message in shared memory buffer (for API)
	logg_fatal_dnsmasq_message(buffer);
}

void log_counter_info(void)
{
	log_info(" -> Total DNS queries: %u", counters->queries);
	log_info(" -> Cached DNS queries: %u", get_cached_count());
	log_info(" -> Forwarded DNS queries: %u", get_forwarded_count());
	log_info(" -> Blocked DNS queries: %u", get_blocked_count());
	log_info(" -> Unknown DNS queries: %u", counters->status[QUERY_UNKNOWN]);
	log_info(" -> Unique domains: %u", counters->domains);
	log_info(" -> Unique clients: %u", counters->clients);
	log_info(" -> DNS cache records: %u", counters->dns_cache_size);
	log_info(" -> Known forward destinations: %u", counters->upstreams);
}

// Print FTL version information
void log_FTL_version(const bool crashreport)
{
	log_info("FTL branch: %s", git_branch());
	log_info("FTL version: %s", get_FTL_version());
	log_info("FTL commit: %s", git_hash());
	log_info("FTL date: %s", git_date());
	if(crashreport)
	{
		char *username_now = getUserName();
		log_info("FTL user: started as %s, ended as %s", username, username_now);
		free(username_now);
	}
	else
		log_info("FTL user: %s", username);
	log_info("Compiled for %s using %s", ftl_arch(), ftl_cc());
}

static char *FTLversion = NULL;
// Return FTL version
const char __attribute__ ((malloc)) *get_FTL_version(void)
{
	// Obtain FTL version if not already determined
	if(FTLversion == NULL)
	{
		if(strlen(git_tag()) > 1 )
		{
			if (strlen(git_version()) > 1)
			{
				// Copy version string if this is a tagged release
				FTLversion = strdup(git_version());
			}

		}
		else if(strlen(git_hash()) > 0)
		{
			// Build special version string when there is a hash
			FTLversion = calloc(13, sizeof(char));
			// Build version by appending 7 characters of the hash to "vDev-"
			snprintf(FTLversion, 13, "vDev-%.7s", git_hash());
		}
		else
		{
			// Fallback for tarball build, etc. without any GIT subsystem
			FTLversion = strdup("UNKNOWN (not a GIT build)");
		}
	}

	return FTLversion;
}

const char __attribute__ ((const)) *get_ordinal_suffix(unsigned int number)
{
	// We only need to handle the last two digits
	const unsigned int last_two = number % 100u;
	// Special case: 11, 12 and 13 get the "th" suffix
	if(last_two >= 11u && last_two <= 13u)
		return "th";
	// Otherwise, the suffix depends on the last digit
	switch(number % 10u)
	{
		case 1u:
			return "st";
		case 2u:
			return "nd";
		case 3u:
			return "rd";
		default:
			return "th";
	}
}

// Deal with C limits for the output buffer
// https://en.wikipedia.org/wiki/C_string_handling
static int binbuf_to_escaped_C_literal(const char *src_buf, size_t src_sz,
                                      char *out_buf, size_t out_sz)
{
	// We need at least 2 bytes space to write one byte
	if(out_sz < 2u)
		return -1;

	size_t used = 0;
	for(size_t i = 0u; i < src_sz; i++)
	{
		char esc = '\0';
		switch(src_buf[i])
		{
			case '\0':
				// Escape these as \0 or \x00 to prevent truncation
				esc = '0';
				break;
			case '\a':
				esc = 'a';
				break;
			case '\b':
				esc = 'b';
				break;
			case '\t':
				esc = 't';
				break;
			case '\n':
				esc = 'n';
				break;
			case '\v':
				esc = 'v';
				break;
			case '\f':
				esc = 'f';
				break;
			case '\r':
				esc = 'r';
				break;
			case '\\':
				esc = '\\';
				break;
			case '"':
				esc = '"';
				break;
			default:
				break;
		}
		if(esc == '\0')
		{
			// Copy as-is, but respect the output size limit
			if(used + 1u >= out_sz)
				break;
			out_buf[used++] = src_buf[i];
		}
		else
		{
			// Escape sequence: two bytes
			if(used + 2u > out_sz)
				break;
			out_buf[used++] = '\\';
			out_buf[used++] = esc;
		}
	}
	out_buf[used] = '\0';
	return (int)used;
}

// Escape a string with C style escape sequences
char * __attribute__ ((malloc)) escape_string(const char *input)
{
	if(input == NULL)
		return strdup("");
	const size_t inputlen = strlen(input);
	if(inputlen == 0)
		return strdup("");
	const size_t alloc = inputlen * 2u + 1u;
	char *output = calloc(alloc, sizeof(char));
	(void)binbuf_to_escaped_C_literal(input, inputlen, output, alloc);
	return output;
}

// Escape a string with C style escape sequences (may contain NUL bytes)
char * __attribute__((malloc)) escape_data(const char *src_buf, size_t src_sz)
{
	const size_t alloc = src_sz * 2u + 1u;
	char *output = calloc(alloc, sizeof(char));
	(void)binbuf_to_escaped_C_literal(src_buf, src_sz, output, alloc);
	return output;
}

const char * __attribute__ ((pure)) short_path(const char *full_path)
{
	const char *shorter = strstr(full_path, "src/");
	return shorter != NULL ? shorter : full_path;
}

void print_FTL_version(void)
{
    printf("Pi-hole FTL %s\n", get_FTL_version());
}

static const char *skipStr(const char *startstr, const char *message)
{
	// Skip leading string if found
	const size_t startlen = strlen(startstr);
	if(strncmp(startstr, message, startlen) == 0)
		return message + startlen;
	else
		return message;
}

void dnsmasq_diagnosis_warning(const char *message)
{
	// Crop away any existing initial "warning: "
	logg_warn_dnsmasq_message(skipStr("warning: ", message));
}

void add_to_fifo_buffer(const enum fifo_logs which, const char *payload, const char *prio, const size_t length, const double timestamp)
{
	// Do not try to log when shared memory isn't initialized yet
	if(!fifo_log)
		return;

	// Nothing to store. A zero length would index message[idx][-1] when
	// looking for a trailing newline below, so drop the record entirely
	// rather than consuming a slot for it
	if(payload == NULL || length == 0)
		return;

	unsigned int idx = fifo_log->logs[which].next_id++;
	if(idx >= LOG_SIZE)
	{
		// Log is full, move everything one slot forward to make space for a new record at the end
		// This pruges the oldest message from the list (it is overwritten by the second message)
		memmove(&fifo_log->logs[which].message[0][0], &fifo_log->logs[which].message[1][0], (LOG_SIZE - 1u) * MAX_MSG_FIFO);
		memmove(&fifo_log->logs[which].prio[0], &fifo_log->logs[which].prio[1], (LOG_SIZE - 1u) * sizeof(fifo_log->logs[which].prio[0]));
		memmove(&fifo_log->logs[which].timestamp[0], &fifo_log->logs[which].timestamp[1], (LOG_SIZE - 1u) * sizeof(fifo_log->logs[which].timestamp[0]));
		idx = LOG_SIZE - 1u;
	}

	// Copy string
	// We need to use the pre-allocated buffer in shared memory as we share
	// this FIFO with forks and friends, so we can't use strdup()
	// Reserve one byte for the NUL terminator so we never write past the end
	// of message[idx] (which is MAX_MSG_FIFO bytes, indices 0..MAX_MSG_FIFO-1)
	size_t copybytes = length < (MAX_MSG_FIFO - 1u) ? length : (MAX_MSG_FIFO - 1u);
	memcpy(fifo_log->logs[which].message[idx], payload, copybytes);

	// Zero-terminate buffer, truncate newline if found
	if(fifo_log->logs[which].message[idx][copybytes - 1u] == '\n')
		fifo_log->logs[which].message[idx][copybytes - 1u] = '\0';
	else
		fifo_log->logs[which].message[idx][copybytes] = '\0';

	// Replace last bytes by "...\0" if we truncated the message
	if(length >= MAX_MSG_FIFO)
	{
		fifo_log->logs[which].message[idx][MAX_MSG_FIFO - 4] = '.';
		fifo_log->logs[which].message[idx][MAX_MSG_FIFO - 3] = '.';
		fifo_log->logs[which].message[idx][MAX_MSG_FIFO - 2] = '.';
		fifo_log->logs[which].message[idx][MAX_MSG_FIFO - 1] = '\0';
	}

	// Set timestamp
	fifo_log->logs[which].timestamp[idx] = timestamp;

	// Set prio (if available)
	fifo_log->logs[which].prio[idx] = prio;
}

bool flush_dnsmasq_log(void)
{
	const double mintime = double_time();

	// Ask the logger thread to drain its queue, clear the in-memory dnsmasq
	// FIFO and truncate pihole.log.  This is the single point where the
	// pihole.log file is modified outside the usual append path.
	const int trunc_err = logger_flush();

	// Clean internal datastructure
	runGC(time(NULL), NULL, true);

	// Flush last 24 hours of on-disk database (even if the truncation above
	// failed; the log file is then just left non-empty)
	if(!delete_old_queries_from_db(false, mintime))
	{
		log_err("Could not flush on-disk database");
		return false;
	}

	// Report a failed truncation now
	if(trunc_err == -1)
		log_warn("Could not truncate pihole.log: no log file is open");
	else if(trunc_err > 0)
		log_err("Could not truncate pihole.log: %s", strerror(trunc_err));

	if(trunc_err != 0)
		return false;

	log_info("Log has been flushed due to API request");

	return true;
}
