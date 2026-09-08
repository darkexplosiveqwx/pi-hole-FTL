/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Asynchronous logging subsystem
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef LOGGER_H
#define LOGGER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

// enum fifo_logs, enum log_destination
#include "enums.h"

// Maximum message size in bytes (including the NUL terminator).  This is the
// single truncation point for the whole logging subsystem: messages are
// formatted once on the producer side and every sink (FTL.log, pihole.log,
// webserver.log, the FIFO, JSON output and systemd journal) renders the
// canonical record below.  Previously each sink had its own buffer size
// (2048 bytes for the log files, 8192 for JSON/journal) which could lead to
// different truncation depending on the destination.
#define LOGGER_MAX_MESSAGE 2048u

// Number of slots in the lock-free log queue.  Each slot holds one record
// (LOGGER_MAX_MESSAGE bytes plus ~40 bytes of metadata), totalling roughly
// 540 KiB of shared memory.  The size must be a compile time constant so the
// queue can live in shared memory (shared with dnsmasq TCP-query forks).
#define LOGGER_RING_SLOTS 256u

// Eventfd poll timeout for the logger thread.  Producers which are fork
// children must not touch the shared eventfd (fd-number reuse hazard), so
// their records are picked up by this periodic poll instead.
#define LOGGER_POLL_TIMEOUT_MS 20

// Who produced a log record.  Decides which file sink (FTL.log vs.
// webserver.log vs. pihole.log) a record is written to, which FIFO buffer it
// is relayed to and the "component" tag used for JSON/journal output.
enum log_source {
	LOG_SOURCE_FTL,       // _FTL_log()
	LOG_SOURCE_DNSMASQ,   // FTL_dnsmasq_log() (my_syslog())
	LOG_SOURCE_WEBSERVER, // _log_web()
};

// One canonical log record.  Records live in the shared-memory ring, so they
// must never contain pointers or heap-allocated payloads: records produced by
// dnsmasq TCP-query forks are consumed by the main process' logger thread.
struct log_record {
	double ts;               // production time (epoch seconds, double_time())
	int priority;            // syslog priority (see sys/syslog.h)
	enum debug_flag flag;    // FTL debug flag (used by priostr/debugstr)
	enum log_source source;  // who produced the record
	pid_t pid;               // producing process
	pid_t tid;               // producing thread
	bool is_fork;            // pid != main_pid() at production time
	size_t len;              // byte length of message (excluding NUL)
	char func[16];           // dnsmasq component suffix ("-dhcp", "-tftp", ...)
	char message[LOGGER_MAX_MESSAGE];
};

// Fill the process/thread/time fields of a record.  The caller then formats
// the actual message into rec->message, sets rec->len and calls log_ring_push().
void log_record_init(struct log_record *rec, const enum log_source source,
                     const int priority, const enum debug_flag flag);

// Enqueue a record.  Lock-free; never blocks.  When the ring is full the
// record is dropped - low priorities immediately, high priorities (WARNING
// and above) after a bounded retry so the logger thread can catch up.  Returns
// false when the record was dropped.  Safe to call from a crash handler and
// from dnsmasq TCP-query fork children.
bool log_ring_push(struct log_record *rec);

// Initialize the logging subsystem: create the queue in shared memory and the
// eventfd, spawn the logger thread and wait until the configured sinks are
// open.  Called once at startup (open_log_fds(true)) and again after fork()ing
// into the daemon (post-daemonize restart, see logger_stop()).
bool logger_start(void);

// Stop the logger thread, waiting for it to drain the queue.  Pre-fork only.
void logger_stop(void);

// Respawning the consumer thread in the daemonized (double-forked) child.
// fork() retains only the calling thread, so the pre-fork logger thread does
// not exist in this process; a stale copy of its state flags, however, was
// inherited and would make logger_start() skip.  This resets those flags and
// starts a fresh consumer on the inherited ring/eventfd.
void logger_start_after_daemonize(void);

// Final shutdown: stop the logger thread, drain whatever is left and unmap the
// shared-memory queue.  Called at the very end of cleanup().
void logger_shutdown(void);

// Re-read the config-derived sink paths/destination and reopen the sinks.
// Main thread only (open_log_fds(false)).
void logger_reconfigure(void);

// Block until the log queue is drained, the in-memory FIFO dnsmasq buffer is
// cleared and pihole.log is truncated.  Returns 0 on success, -1 when no
// pihole.log is open, or a positive errno when the truncation failed.  Used by
// the API flush action.
int logger_flush(void);

// Request a sink reopen from a signal handler (SIGUSR2).  Async-signal-safe:
// only touches atomics and the eventfd.
void logger_sig_reopen(void);

#endif // LOGGER_H