/*
 * save.c
 *
 * Copyright 2007, 2010 by Anthony Howe. All rights reserved.
 */

#define SAVE_UPDATED_HEADERS

/***********************************************************************
 *** Leave this header alone. Its generated from the configure script.
 ***********************************************************************/

#include "config.h"

/***********************************************************************
 ***
 ***********************************************************************/

#ifdef FILTER_SAVE

#include "smtpf.h"

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif
#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif

/***********************************************************************
 ***
 ***********************************************************************/

static const char usage_save_data[] =
  "When set, save the DATA content to a file in the save-dir directory.\n"
"# Intended for testing and diagnosis. The access-map actions SAVE and\n"
"# TRAP can also be used to selectively save messages based on Connect:,\n"
"# From, and To: tags. SAVE keeps a copy of the message and delivers or\n"
"# or rejects it, while TRAP is equivalent to SAVE and DISCARD.\n"
"#"
;
Option optSaveData	= { "save-data",	"-",		usage_save_data };

static const char usage_save_dir[] =
  "A directory where to save output for diagnosis."
;
Option optSaveDir	= { "save-dir",		WORK_DIR,	usage_save_dir };

Option optTrapDir	= { "trap-dir",		WORK_DIR,	usage_save_dir };

typedef struct {
	FILE *fp;
	long eoh;
	char *name;
	char *save_dir;
	char *trap_dir;
} Save;

static Verbose verb_save		= { { "save", "-", "" } };
static FilterContext save_context;

/***********************************************************************
 ***
 ***********************************************************************/

const char *
saveGetName(Session *sess)
{
	Save *save = filterGetContext(sess, save_context);

	return save->name;
}

long
saveGetEOH(Session *sess)
{
#ifdef SAVE_UPDATED_HEADERS
	Save *save = filterGetContext(sess, save_context);

	return save->eoh;
#else
	return sess->msg.eoh;
#endif
}

void
saveSetSaveDir(Session *sess, const char *dir)
{
	Save *save;

	if (dir != NULL) {
		save = filterGetContext(sess, save_context);
		free(save->save_dir);
		save->save_dir = strdup(dir);
	}
}

void
saveSetTrapDir(Session *sess, const char *dir)
{
	Save *save;

	if (dir != NULL) {
		save = filterGetContext(sess, save_context);
		free(save->trap_dir);
		save->trap_dir = strdup(dir);
	}
}

int
saveRegister(Session *sess, va_list ignore)
{
	verboseRegister(&verb_save);

	optionsRegister(&optSaveData, 0);
	optionsRegister(&optSaveDir, 0);
	optionsRegister(&optTrapDir, 0);

	save_context = filterRegisterContext(sizeof (Save));

	return SMTPF_CONTINUE;
}

int
saveInit(Session *null, va_list ignore)
{
	LOG_TRACE0(530, saveInit);

	if (*optSaveDir.string == '\0') {
		syslog(LOG_ERR, LOG_NUM(574) "save-dir must be defined");
/*{NEXT}*/
		exit(1);
	}

	return SMTPF_CONTINUE;
}

int
saveConnect(Session *sess, va_list ignore)
{
	Save *save = filterGetContext(sess, save_context);

	LOG_TRACE(sess, 575, saveConnect);

	save->save_dir = NULL;
	save->trap_dir = NULL;
	save->name = NULL;
	save->eoh = 0;
	save->fp = NULL;

	return SMTPF_CONTINUE;
}

int
saveRset(Session *sess, va_list ignore)
{
	Save *save = filterGetContext(sess, save_context);

	LOG_TRACE(sess, 576, saveRset);

	if (save->fp != NULL) {
		(void) fclose(save->fp);
		save->fp = NULL;
	}

	/*** NOTE avastd, clamd, fpscand, savdid, spamd2 modules will bit-wise
	 *** OR 2 with the optSaveData.value when they require .msg files
	 ***/
	if ((optSaveData.value & 1) == 0 && save->name != NULL && unlink(save->name) && errno != ENOENT) {
		syslog(LOG_ERR, LOG_MSG(577) "delete error \"%s\": %s (%d)", LOG_ARGS(sess), save->name, strerror(errno), errno);
/*{NEXT}*/
	}

	free(save->name);
	save->name = NULL;

	free(save->save_dir);
	save->save_dir = NULL;

	free(save->trap_dir);
	save->trap_dir = NULL;

	return SMTPF_CONTINUE;
}

int
saveHeaders(Session *sess, va_list args)
{
	Save *save = filterGetContext(sess, save_context);

	LOG_TRACE(sess, 578, saveHeaders);

	if (save->save_dir == NULL && *optSaveDir.string != '\0')
		save->save_dir = strdup(optSaveDir.string);
	if (save->trap_dir == NULL && *optTrapDir.string != '\0')
		save->trap_dir = strdup(optTrapDir.string);

	if (save->save_dir != NULL
	&& (optSaveData.value || MSG_ANY_SET(sess, MSG_SAVE|MSG_TAG))) {
		(void) snprintf(sess->input, sizeof (sess->input), "%s/%s.tmp", save->save_dir, sess->msg.id);
		if ((save->name = strdup(sess->input)) == NULL) {
			syslog(LOG_ERR, LOG_MSG(579) "temp. file name \"%s\": %s (%d)", LOG_ARGS(sess), sess->input, strerror(errno), errno);
/*{NEXT}*/
		} else if ((save->fp = fopen(save->name, "wb")) == NULL) {
			syslog(LOG_ERR, LOG_MSG(580) "create error \"%s\": %s (%d)", LOG_ARGS(sess), save->name, strerror(errno), errno);
/*{LOG
See <a href="summary.html#opt_save_data">save-data</a>,
<a href="summary.html#opt_save_dir">save-dir</a> option.
In addition, the
<a href="summary.html#opt_avastd_socket">avastd-socket</a>,
<a href="summary.html#opt_fpscand_socket">fpscand-socket</a>,
and <a href="summary.html#opt_spamd_socket">spamd-socket</a>
options also rely on the
<a href="summary.html#opt_save_dir">save-dir</a>
option being defined in order to function.
}*/
		} else {
			cliFdCloseOnExec(fileno(save->fp), 1);
			(void) pathSetPermsByName(save->name, optRunUser.string, optRunGroup.string, 0660);
			if (verb_save.option.value) {
				struct stat sb;
				(void) fstat(fileno(save->fp), &sb);
				syslog(LOG_DEBUG, LOG_MSG(581) "\"%s\" user=%d group=%d perms=%o", LOG_ARGS(sess), save->name, sb.st_uid, sb.st_gid, sb.st_mode);
			}
#ifdef SAVE_UPDATED_HEADERS
{
		 	char **hdr;
			for (hdr = (char **) VectorBase(sess->msg.headers); *hdr != NULL; hdr++) {
				fputs(*hdr, save->fp);
			}
			fputs(CRLF, save->fp);
			save->eoh = ftell(save->fp);
}
#endif
		}
	}
#ifndef SAVE_UPDATED_HEADERS
	save->eoh = sess->msg.eoh;
#endif
	return SMTPF_CONTINUE;
}

int
saveContent(Session *sess, va_list args)
{
	long size;
	Save *save;
	unsigned char *chunk;

	save = filterGetContext(sess, save_context);
	chunk = va_arg(args, unsigned char *);
	size = va_arg(args, long);

#ifndef SAVE_UPDATED_HEADERS
	if (chunk == sess->msg.chunk0 + sess->msg.eoh) {
		chunk = sess->msg.chunk0;
		size += sess->msg.eoh;
	}
#endif
	if (verb_trace.option.value)
		syslog(LOG_DEBUG, LOG_MSG(582) "saveContent(%lx, chunk=%lx, size=%ld)", LOG_ARGS(sess), (long) sess, (long) chunk, size);

	if (save->fp != NULL)
		(void) fwrite(chunk, 1, size, save->fp);

	return SMTPF_CONTINUE;
}

int
saveDot(Session *sess, va_list ignore)
{
	Save *save = filterGetContext(sess, save_context);

	LOG_TRACE(sess, 583, saveDot);

	if (save->fp != NULL) {
		(void) fclose(save->fp);
		save->fp = NULL;

#ifdef __unix__
/* No hard links under Windows. */
		if (MSG_IS_SET(sess, MSG_TRAP, MSG_TRAP) && save->trap_dir != NULL) {
			(void) snprintf(sess->input, sizeof (sess->input), "%s/%s.trap", save->trap_dir, sess->msg.id);
			if (link(save->name, sess->input))
				syslog(LOG_ERR, LOG_MSG(876) "hard link(%s, %s) failed: %s (%d)", LOG_ARGS(sess), save->name, sess->input, strerror(errno), errno);
		} else if (MSG_IS_SET(sess, MSG_SAVE, MSG_SAVE) && save->save_dir != NULL) {
			(void) snprintf(sess->input, sizeof (sess->input), "%s/%s.msg", save->save_dir, sess->msg.id);
			if (link(save->name, sess->input))
				syslog(LOG_ERR, LOG_MSG(877) "hard link(%s, %s) failed: %s (%d)", LOG_ARGS(sess), save->name, sess->input, strerror(errno), errno);
		}
#endif
	}

	return SMTPF_CONTINUE;
}

int
saveClose(Session *sess, va_list ignore)
{
	saveRset(sess, ignore);
	return SMTPF_CONTINUE;
}

#endif /* FILTER_SAVE */
