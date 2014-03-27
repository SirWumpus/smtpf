/*
 * stats.h
 *
 * Copyright 2006, 2007 by Anthony Howe. All rights reserved.
 */

#ifndef __stats_h__
#define __stats_h__			1

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
 ***
 ***********************************************************************/

#include <com/snert/lib/util/timer.h>

#define STATS_ROUTE

typedef enum {
	STATS_TABLE_GENERAL	= 0,
	STATS_TABLE_CONNECT	= 1,
	STATS_TABLE_MAIL	= 2,
	STATS_TABLE_RCPT	= 3,
	STATS_TABLE_DATA	= 4,
	STATS_TABLE_MSG		= 5,
	STATS_TABLE_LENGTH	= 6,
	STATS_TABLE_SIZE	= 7,
} STATS_TABLE;

#define STATS_TICK		360		/* seconds per tick */
#define	STATS_INTERVALS		10		/* intervals per window */
#define STATS_WINDOW_SIZE	3600		/* seconds per window */

typedef struct {
	unsigned long ticks;
	unsigned long count;
} StatsInterval;

typedef struct {
	STATS_TABLE table;
	const char *name;
	int is_max_of_intervals;
	unsigned long hourly;
	unsigned long runtime;
	StatsInterval intervals[STATS_INTERVALS];
} Stats;

extern Stats stat_high_load_avg_1;
extern Stats stat_high_load_avg_5;
extern Stats stat_high_load_avg_15;
extern Stats stat_load_avg_1;
extern Stats stat_load_avg_5;
extern Stats stat_load_avg_15;
extern Stats stat_low_load_avg_1;
extern Stats stat_low_load_avg_5;
extern Stats stat_low_load_avg_15;

extern Stats stat_high_connections;
extern Stats stat_high_session_time;
extern Stats stat_high_connections_per_second;
extern Stats stat_high_connections_per_minute;
extern Stats stat_connections_per_minute;
extern Stats stat_total_kb;

extern Stats stat_open_files;
extern Stats stat_high_open_files;

extern Stats stat_connect_count;
extern Stats stat_connect_dropped;
extern Stats stat_clean_quit;
extern Stats stat_client_io_error;
extern Stats stat_client_timeout;
extern Stats stat_client_is_2nd_mx;
extern Stats stat_client_pipelining_seen;
extern Stats stat_client_pipelining_reject;
extern Stats stat_server_io_error;
extern Stats stat_admin_commands;
extern Stats stat_auth_pass;
extern Stats stat_auth_fail;
extern Stats stat_concurrent;
extern Stats stat_connect_lan;
extern Stats stat_connect_localhost;
extern Stats stat_connect_relay;
extern Stats stat_ehlo_no_helo;
extern Stats stat_helo_schizophrenic;
extern Stats stat_rfc2821_command_length;
extern Stats stat_smtp_command_non_ascii;
extern Stats stat_smtp_drop_after;
extern Stats stat_smtp_drop_unknown;
extern Stats stat_smtp_reject_delay;

extern Stats stat_mail_count;
extern Stats stat_null_sender;
extern Stats stat_call_back_cache;
extern Stats stat_call_back_made;
extern Stats stat_cli_envelope;
extern Stats stat_grey_continue;
extern Stats stat_grey_tempfail;
extern Stats stat_mail_drop;
extern Stats stat_mail_parse;
extern Stats stat_mail_reject;
extern Stats stat_mail_tempfail;

extern Stats stat_rcpt_count;
extern Stats stat_rcpt_drop;
extern Stats stat_rcpt_parse;
extern Stats stat_rcpt_reject;
extern Stats stat_rcpt_tempfail;
extern Stats stat_rcpt_unknown;
extern Stats stat_rcpt_relay_denied;
extern Stats stat_quit_after_ehlo;
extern Stats stat_quit_after_helo;
extern Stats stat_quit_after_rcpt;
extern Stats stat_msg_queue;

extern Stats stat_forward_helo_tempfail;
extern Stats stat_forward_helo_reject;
extern Stats stat_forward_mail_tempfail;
extern Stats stat_forward_mail_reject;
extern Stats stat_forward_rcpt_tempfail;
extern Stats stat_forward_rcpt_reject;

extern Stats stat_data_count;
extern Stats stat_data_accept;
extern Stats stat_data_drop;
extern Stats stat_data_reject;
extern Stats stat_data_tempfail;
extern Stats stat_data_354;

extern Stats stat_msg_count;
extern Stats stat_msg_accept;
extern Stats stat_msg_discard;
extern Stats stat_msg_drop;
extern Stats stat_msg_reject;
extern Stats stat_msg_tempfail;
extern Stats stat_msg_trap;
extern Stats stat_dsn_sent;
extern Stats stat_cli_content;
extern Stats stat_grey_content;
extern Stats stat_infected;
extern Stats stat_junk_mail;
extern Stats stat_line_length;
extern Stats stat_message_limit;
extern Stats stat_message_size;
extern Stats stat_strict_dot;
extern Stats stat_disconnect_after_dot;
extern Stats stat_virus_infected;

extern Vector stats;
extern time_t start_time;
extern int stats_table_indices[STATS_TABLE_SIZE];

extern Option optStatsMap;

extern Verbose verb_stats;

extern int statsRegister0(Session *sess, va_list ignore);

extern void statsInit(void);
extern void statsFini(void);
extern void statsSave(void);
extern void statsLoad(void);
extern int  statsRegister(Stats *stat);
extern void statsLock(void);
extern void statsUnlock(void);
extern void statsTimerTask(Timer *);
extern void stats_at_exit(void);

/*
 * Not mutex protected.
 */
extern unsigned long stats_get_sum_window(Stats *stat);
extern unsigned long stats_get_max_window(Stats *stat);
extern void stats_add_window(Stats *stat, unsigned long value);
extern void stats_set_window(Stats *stat, unsigned long value);

/*
 * Mutex protected.
 */
extern void statsCount(Stats *stat);
extern void statsGet(Stats *stat, Stats *out);
extern unsigned long statsGetHourly(Stats *stat);
extern unsigned long statsGetWindow(Stats *stat);
extern unsigned long statsGetRuntime(Stats *stat);
extern void statsSetValue(Stats *stat, unsigned long value);
extern void statsAddValue(Stats *stat, unsigned long value);
extern void statsSetHighWater(Stats *stat, unsigned long value, int log);
extern void statsSetLowWater(Stats *stat, unsigned long value, int log);
extern void statsGetLoadAvg(void);

#ifdef STATS_ROUTE
extern void statsRoute(Session *sess, int smtpf_code);
#endif

extern int statsCommand(Session *sess);

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef  __cplusplus
}
#endif

#endif /* __stats_h__ */
