/*
 * SPDX-FileCopyrightText: 2026 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include "subjects.h"
#include "base_model.h"

#include "logic.h"
#include "privilege.h"
#include "service.h"

#include "lvgl.h"

#include <future>
#include <memory>
#include <string>
#include <vector>

namespace viewmodel {

// One line on the Rules page: a ufw rule, or a My network template.
struct RuleEntry {
    std::string text;
    bool is_template = false;
    int template_id = 0;
    bool v6 = false;
    std::string raw; // tuple, for deleting user rules
};

// One line on the Networks page.
struct NetworkEntry {
    std::string text;
    bool current = false;
    bool whitelisted = false;
    std::string key;
    std::string subnet4;
};

// A change waiting on the Confirm page.
struct PendingChange {
    enum class Phase { Checking, Ready, Applying, Error };
    std::string title;                    // "Add rule", "Delete rule", ...
    std::string command;                  // shown to the user
    std::vector<std::string> helper_args; // what runs on Enter
    std::vector<std::string> dry_run_args;// ufw args to dry-run first, may be empty
    std::string note;                     // extra line (dry-run summary, "cannot preview")
    std::string warning;                  // SSH lockout warning, empty if none
    bool acknowledged = false;            // warning seen once, Enter again applies
    Phase phase = Phase::Ready;
    model::AppPage return_page = model::AppPage::Status;
    uint32_t request = 0;                 // service request being waited on
};

class BaseViewModel {
public:
    BaseViewModel();
    ~BaseViewModel();

    BaseViewModel(const BaseViewModel&) = delete;
    BaseViewModel& operator=(const BaseViewModel&) = delete;

    void start();
    void tick(); // from an LVGL timer on the UI thread

    // ---- shared subjects ----
    lv_subject_t* title_subject();
    lv_subject_t* dark_mode_subject();
    lv_subject_t* current_page_subject();
    lv_subject_t* quit_requested_subject();
    lv_subject_t* revision_subject();  // bumps whenever anything shown may have changed
    lv_subject_t* notice_subject();    // short success messages for a toast

    bool is_dark_mode() const;
    void set_dark_mode(bool enabled);
    void toggle_dark_mode();
    model::AppPage current_page() const;
    void request_quit();
    bool busy() const;

    // Left/Right on main pages; Esc on sub-pages.
    void next_page(int delta);
    void show_main_page(int index); // 0..3: Status, Rules, Ports, Networks
    void back();

    // ---- password ----
    lv_subject_t* password_mask_subject();
    lv_subject_t* password_message_subject();
    lv_subject_t* password_busy_subject();
    void password_append(char c);
    void password_backspace();
    void password_submit();

    // ---- data ----
    const fw::State& state() const { return state_; }
    bool loaded() const { return loaded_; }
    const std::string& load_error() const { return load_error_; }
    const std::vector<RuleEntry>& rule_entries() const { return rule_entries_; }
    const std::vector<fw::PortRow>& port_rows() const { return port_rows_; }
    const std::vector<fw::PortEntry>& port_entries() const { return port_entries_; }
    const std::vector<NetworkEntry>& network_entries() const { return network_entries_; }
    const fw::Network* current_network() const;
    bool current_network_whitelisted() const;

    // ---- selections ----
    int rules_index() const { return rules_index_; }
    int networks_index() const { return networks_index_; }
    int ports_index() const { return ports_index_; }
    void move_selection(int delta);

    // ---- actions (each opens the Confirm page) ----
    void toggle_enable();
    void toggle_whitelist();
    void undo();
    void delete_selected_rule();
    void remove_selected_network();
    // Ports page: Blocked -> LAN -> Allowed, applied at once (Confirm only for SSH lockout)
    void toggle_selected_port();
    void refresh();

    // ---- add-rule form ----
    enum class FormField { Action, Direction, Port, Proto, Source, CustomSource, Comment, Count };
    void open_add_rule();
    const fw::RuleForm& form() const { return form_; }
    int form_field() const { return form_field_; }
    const std::string& form_error() const { return form_error_; }
    static const char* form_field_label(int field);
    std::string form_field_value(int field) const;
    bool form_field_editable(int field) const;  // typed text
    bool form_field_visible(int field) const;
    void form_move(int delta);
    void form_cycle(int delta);
    void form_type(char c);
    void form_backspace();
    void form_apply_preset(int index);
    void form_submit();

    // ---- free-form ----
    void open_freeform();
    const std::string& freeform_text() const { return freeform_text_; }
    const std::string& freeform_error() const { return freeform_error_; }
    void freeform_type(char c);
    void freeform_backspace();
    void freeform_submit();

    // ---- confirm ----
    const PendingChange& pending() const { return pending_; }
    void confirm_accept();

    // ---- message ----
    const std::string& message_title() const { return message_title_; }
    const std::string& message_text() const { return message_text_; }

private:
    void show_page(model::AppPage page);
    void update_title(model::AppPage page);
    void bump();
    void notice(const std::string& text);
    void rebuild_views();
    void open_confirm(PendingChange change);
    void finish_dry_run(const fw::FirewallService::Result& result);
    void finish_apply(const fw::FirewallService::Result& result);
    void show_message(const std::string& title, const std::string& text,
                      model::AppPage return_page);
    void publish_password_mask();

    model::BaseModel model_;
    fw::Privilege privilege_;
    std::unique_ptr<fw::FirewallService> service_;
    uint32_t service_revision_ = 0;
    uint32_t refresh_request_ = 0;

    fw::State state_;
    bool loaded_ = false;
    std::string load_error_;
    std::vector<RuleEntry> rule_entries_;
    std::vector<fw::PortRow> port_rows_;
    std::vector<fw::PortEntry> port_entries_;
    int ports_index_ = 0;
    std::vector<NetworkEntry> network_entries_;
    int rules_index_ = 0;
    int networks_index_ = 0;

    fw::RuleForm form_;
    int form_field_ = static_cast<int>(FormField::Port);
    std::string form_error_;

    std::string freeform_text_;
    std::string freeform_error_;

    PendingChange pending_;

    std::string message_title_;
    std::string message_text_;
    model::AppPage message_return_ = model::AppPage::Status;

    std::string password_input_;
    std::future<bool> auth_future_;

    reactive::StringSubject<32> title_subject_;
    reactive::BoolSubject dark_mode_subject_;
    reactive::IntSubject current_page_subject_;
    reactive::BoolSubject quit_requested_subject_;
    reactive::IntSubject revision_subject_;
    reactive::StringSubject<96> notice_subject_;
    reactive::StringSubject<64> password_mask_subject_;
    reactive::StringSubject<64> password_message_subject_;
    reactive::BoolSubject password_busy_subject_;
};

} // namespace viewmodel
