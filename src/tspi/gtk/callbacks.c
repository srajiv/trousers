
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004
 *
 */

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <gtk/gtk.h>
#include <string.h>

#include "callbacks.h"
#include "interface.h"
#include "support.h"



/* Callbacks for the simple password dialog */

void
on_inputdialog1_destroy(GtkObject *object, struct userdata *user_data)
{
	gtk_widget_destroy(user_data->window);
	gtk_main_quit();
}


void
on_dialog1_close(GtkDialog *dialog, struct userdata *user_data)
{
	gtk_widget_destroy(user_data->window);
	gtk_main_quit();
}


void
on_cancelbutton1_clicked(GtkButton *button, struct userdata *user_data)
{
	gtk_widget_destroy(user_data->window);
	gtk_main_quit();
}


void
on_okbutton1_clicked(GtkButton *button, struct userdata	*user_data)
{
	const gchar *entry_text = gtk_entry_get_text (GTK_ENTRY(user_data->entry));

	strncpy(user_data->string, entry_text, strlen(entry_text)+1);
	gtk_widget_destroy(user_data->window);

	gtk_main_quit();
}


gboolean
enter_event(GtkWidget *widget, struct userdata *user_data)
{
	const gchar *entry_text = gtk_entry_get_text (GTK_ENTRY(user_data->entry));

	strncpy(user_data->string, entry_text, strlen(entry_text)+1);
	gtk_widget_destroy(user_data->window);

	gtk_main_quit();
	return TRUE;
}


/* Callbacks for the new password dialog */

void
on_entryPassword_activate(GtkEntry *entry, struct userdata *user_data)
{
	gchar *entryPass_text = gtk_entry_get_text (GTK_ENTRY(user_data->entryPass));
	gchar *entryConf_text = gtk_entry_get_text (GTK_ENTRY(user_data->entryConf));
	int len = strlen(entryConf_text);

	if (len == 0) {
		gtk_widget_grab_focus(user_data->entryConf);
		return;
	}

	/* Compare the two text boxes, if they're equal, we're done */
	if(len && !memcmp(entryPass_text, entryConf_text, len)) {
		strncpy(user_data->string, entryConf_text, len + 1);
		gtk_widget_destroy(user_data->window);
		gtk_main_quit();
	} else {
		gtk_widget_grab_focus(user_data->entryConf);
	}
}

void
on_entryConfirm_activate(GtkEntry *entry, struct userdata *user_data)
{
	gchar *entryPass_text = gtk_entry_get_text (GTK_ENTRY(user_data->entryPass));
	gchar *entryConf_text = gtk_entry_get_text (GTK_ENTRY(user_data->entryConf));
	int len = strlen(entryConf_text);

	/* Compare the two text boxes, if they're equal, we're done */
	if(len && !memcmp(entryPass_text, entryConf_text, len)) {
		strncpy(user_data->string, entryConf_text, len + 1);
		gtk_widget_destroy(user_data->window);
		gtk_main_quit();
	} else {
		gtk_widget_grab_focus(user_data->entryPass);
	}
}

void
on_cancelbutton2_clicked(GtkButton *button, struct userdata *user_data)
{
	gtk_widget_destroy(user_data->window);
	gtk_main_quit();
}

void
on_okbutton2_clicked(GtkButton *button, struct userdata *user_data)
{
	gchar *entryPass_text = gtk_entry_get_text (GTK_ENTRY(user_data->entryPass));
	gchar *entryConf_text = gtk_entry_get_text (GTK_ENTRY(user_data->entryConf));
	int len = strlen(entryConf_text);

	/* Compare the two text boxes, if they're equal, we're done */
	if(len && !memcmp(entryPass_text, entryConf_text, len)) {
		strncpy(user_data->string, entryConf_text, len + 1);
		gtk_widget_destroy(user_data->window);
		gtk_main_quit();
	} else {
		gtk_widget_grab_focus(user_data->entryPass);
	}
}





