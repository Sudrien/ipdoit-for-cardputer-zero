/*
 * SPDX-FileCopyrightText: 2026 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */

#include "base_viewmodel.h"

#include "parse.h"

#include <algorithm>
#include <cctype>
#include <chrono>

namespace viewmodel {
namespace {

using model::AppPage;
using fw::FirewallService;

constexpr size_t kMaxPassword = 128;
constexpr size_t kMaskShown = 24;
constexpr size_t kMaxText = 120;

void wipe(std::string& s) {
    volatile char* p = s.empty() ? nullptr : &s[0];
    for (size_t i = 0; i < s.size(); ++i) {
        p[i] = 0;
    }
    s.clear();
}

std::string first_lines(const std::string& text, int n) {
    std::string out;
    size_t pos = 0;
    for (int i = 0; i < n && pos < text.size(); ++i) {
        const auto end = text.find('\n', pos);
        if (!out.empty()) out += '\n';
        out += text.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
        if (end == std::string::npos) break;
        pos = end + 1;
    }
    return out;
}

std::string error_lines(const std::string& text) {
    std::string out;
    size_t pos = 0;
    while (pos < text.size()) {
        auto end = text.find('\n', pos);
        if (end == std::string::npos) end = text.size();
        const auto line = text.substr(pos, end - pos);
        if (line.rfind("ERROR", 0) == 0 || line.rfind("error", 0) == 0 ||
            line.rfind("WARN", 0) == 0) {
            if (!out.empty()) out += '\n';
            out += line;
        }
        pos = end + 1;
    }
    return out.empty() ? first_lines(text, 4) : out;
}

std::vector<fw::Rule> without_raw(const std::vector<fw::Rule>& rules, const std::string& raw) {
    std::vector<fw::Rule> out;
    for (const auto& r : rules) {
        if (r.raw != raw) out.push_back(r);
    }
    return out;
}

std::vector<fw::Rule> without_template(const std::vector<fw::Rule>& rules, int id) {
    std::vector<fw::Rule> out;
    for (const auto& r : rules) {
        if (r.mynet_id() != id) out.push_back(r);
    }
    return out;
}

const char* kActions[] = {"allow", "deny", "reject", "limit"};
const char* kProtos[] = {"tcp", "udp", "any"};

template <size_t N>
std::string cycle(const char* const (&list)[N], const std::string& cur, int delta) {
    int i = 0;
    for (size_t k = 0; k < N; ++k) {
        if (cur == list[k]) i = static_cast<int>(k);
    }
    i = ((i + delta) % static_cast<int>(N) + static_cast<int>(N)) % static_cast<int>(N);
    return list[i];
}

} // namespace

BaseViewModel::BaseViewModel()
    : service_(std::make_unique<FirewallService>(privilege_)),
      title_subject_(model_.app_title()),
      dark_mode_subject_(model_.dark_mode()),
      current_page_subject_(static_cast<int>(model_.current_page())),
      quit_requested_subject_(false),
      revision_subject_(0),
      notice_subject_(""),
      password_mask_subject_(""),
      password_message_subject_("Enter your sudo password"),
      password_busy_subject_(false) {}

BaseViewModel::~BaseViewModel() {
    if (auth_future_.valid()) {
        auth_future_.wait();
    }
    wipe(password_input_);
    service_.reset(); // joins the worker before privilege_ goes away
}

// =========================================================== lifecycle

void BaseViewModel::start() {
    privilege_.detect();
    switch (privilege_.mode()) {
        case fw::Privilege::Mode::Unavailable:
            show_message("No root access",
                         "Ipdoit needs sudo (or to run as root) to manage the firewall, and "
                         "sudo was not found.",
                         AppPage::Status);
            break;
        case fw::Privilege::Mode::SudoPassword:
            show_page(AppPage::Password);
            break;
        default:
            show_page(AppPage::Status);
            refresh();
            break;
    }
}

void BaseViewModel::tick() {
    if (auth_future_.valid() &&
        auth_future_.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
        const bool ok = auth_future_.get();
        password_busy_subject_.set(false);
        if (ok) {
            password_message_subject_.set("Enter your sudo password");
            show_page(AppPage::Status);
            refresh();
        }
        else {
            password_message_subject_.set("Wrong password, try again");
        }
    }

    const auto snap = service_->snapshot();
    if (snap.revision == service_revision_) {
        return;
    }
    service_revision_ = snap.revision;

    if (snap.state.ok) {
        state_ = snap.state;
        loaded_ = true;
        load_error_.clear();
    }
    const auto& last = snap.last;
    if (last.id != 0 && last.id == refresh_request_) {
        refresh_request_ = 0;
        if (!last.ok) {
            load_error_ = last.output.empty() ? "could not read the firewall state" : last.output;
        }
    }
    if (last.id != 0 && last.id == pending_.request) {
        pending_.request = 0;
        if (last.op == FirewallService::Op::DryRun) {
            finish_dry_run(last);
        }
        else if (last.op == FirewallService::Op::Apply) {
            finish_apply(last);
        }
    }
    rebuild_views();
    bump();
}

void BaseViewModel::refresh() {
    const auto id = service_->refresh();
    if (id) {
        refresh_request_ = id;
        bump();
    }
}

void BaseViewModel::rebuild_views() {
    rule_entries_.clear();
    for (const auto* list : {&state_.rules4, &state_.rules6}) {
        for (const auto& r : *list) {
            if (r.is_mynet()) continue; // shown once, as its template
            RuleEntry e;
            e.text = fw::describe_rule(r);
            e.v6 = r.v6;
            e.raw = r.raw;
            rule_entries_.push_back(std::move(e));
        }
    }
    for (const auto& t : state_.templates) {
        RuleEntry e;
        e.text = fw::describe_template(t);
        e.is_template = true;
        e.template_id = t.id;
        rule_entries_.push_back(std::move(e));
    }

    port_rows_ = fw::port_rows(state_);
    port_entries_ = fw::port_entries(state_);

    network_entries_.clear();
    for (const auto& n : state_.networks) {
        NetworkEntry e;
        e.current = true;
        e.key = n.key();
        e.subnet4 = n.subnet4;
        e.whitelisted = fw::is_whitelisted(n, state_.whitelist);
        e.text = n.iface + "  " + (n.subnet4.empty() ? n.subnet6 : n.subnet4) +
                 (e.whitelisted ? "  whitelisted" : "  not whitelisted");
        network_entries_.push_back(std::move(e));
    }
    for (const auto& w : state_.whitelist) {
        bool current = false;
        for (const auto& e : network_entries_) {
            if (e.current && e.key == w.key && e.subnet4 == w.subnet4) current = true;
        }
        if (current) continue;
        NetworkEntry e;
        e.key = w.key;
        e.subnet4 = w.subnet4;
        e.whitelisted = true;
        e.text = w.name + "  " + w.subnet4;
        network_entries_.push_back(std::move(e));
    }

    const int rn = static_cast<int>(rule_entries_.size());
    rules_index_ = std::clamp(rules_index_, 0, std::max(0, rn - 1));
    const int pn = static_cast<int>(port_entries_.size());
    ports_index_ = std::clamp(ports_index_, 0, std::max(0, pn - 1));
    const int nn = static_cast<int>(network_entries_.size());
    networks_index_ = std::clamp(networks_index_, 0, std::max(0, nn - 1));
}

const fw::Network* BaseViewModel::current_network() const {
    return fw::primary_network(state_.networks);
}

bool BaseViewModel::current_network_whitelisted() const {
    const auto* n = current_network();
    return n && fw::is_whitelisted(*n, state_.whitelist);
}

// =========================================================== shared

lv_subject_t* BaseViewModel::title_subject() { return title_subject_.native(); }
lv_subject_t* BaseViewModel::dark_mode_subject() { return dark_mode_subject_.native(); }
lv_subject_t* BaseViewModel::current_page_subject() { return current_page_subject_.native(); }
lv_subject_t* BaseViewModel::quit_requested_subject() { return quit_requested_subject_.native(); }
lv_subject_t* BaseViewModel::revision_subject() { return revision_subject_.native(); }
lv_subject_t* BaseViewModel::notice_subject() { return notice_subject_.native(); }

bool BaseViewModel::is_dark_mode() const { return model_.dark_mode(); }

void BaseViewModel::set_dark_mode(bool enabled) {
    model_.set_dark_mode(enabled);
    dark_mode_subject_.set(model_.dark_mode());
}

void BaseViewModel::toggle_dark_mode() {
    model_.toggle_dark_mode();
    dark_mode_subject_.set(model_.dark_mode());
}

AppPage BaseViewModel::current_page() const { return model_.current_page(); }

void BaseViewModel::request_quit() {
    quit_requested_subject_.set(true);
}

bool BaseViewModel::busy() const {
    return service_->busy();
}

void BaseViewModel::show_page(AppPage page) {
    update_title(page);
    model_.set_current_page(page);
    current_page_subject_.set(static_cast<int>(page));
}

// Title: "Ipdoit  Ports" on the main pages (the footer shows "<| / |> (3)"), just "Ipdoit"
// elsewhere.
void BaseViewModel::update_title(AppPage page) {
    static const char* const kNames[] = {"Status", "Rules", "Ports", "Networks"};
    std::string title = model_.app_title();
    for (int i = 0; i < model::kMainPageCount; ++i) {
        if (model::kMainPages[i] == page) title += std::string("  ") + kNames[i];
    }
    title_subject_.set(title.c_str());
}

void BaseViewModel::show_main_page(int index) {
    if (index >= 0 && index < model::kMainPageCount) {
        show_page(model::kMainPages[index]);
    }
}

void BaseViewModel::bump() {
    revision_subject_.set(revision_subject_.value() + 1);
}

void BaseViewModel::notice(const std::string& text) {
    notice_subject_.set("");
    notice_subject_.set(text.c_str());
}

void BaseViewModel::next_page(int delta) {
    const auto cur = model_.current_page();
    int i = 0;
    for (int k = 0; k < model::kMainPageCount; ++k) {
        if (model::kMainPages[k] == cur) i = k;
    }
    i = ((i + delta) % model::kMainPageCount + model::kMainPageCount) % model::kMainPageCount;
    show_page(model::kMainPages[i]);
}

void BaseViewModel::back() {
    switch (model_.current_page()) {
        case AppPage::Password:
            request_quit();
            break;
        case AppPage::Status:
        case AppPage::Rules:
        case AppPage::Ports:
        case AppPage::Networks:
            request_quit();
            break;
        case AppPage::AddRule:
        case AppPage::FreeForm:
            show_page(AppPage::Rules);
            break;
        case AppPage::Confirm:
            if (pending_.phase == PendingChange::Phase::Applying) {
                return; // cannot cancel a change in progress
            }
            {
                const auto back_to = pending_.return_page;
                if (pending_.is_nm_hook_offer) nm_hook_declined_ = true;
                pending_ = PendingChange{};
                show_page(back_to);
            }
            break;
        case AppPage::Message:
            if (privilege_.mode() == fw::Privilege::Mode::Unavailable) {
                request_quit();
                break;
            }
            show_page(message_return_);
            break;
    }
}

void BaseViewModel::show_message(const std::string& title, const std::string& text,
                                 AppPage return_page) {
    message_title_ = title;
    message_text_ = text.size() > 1500 ? text.substr(text.size() - 1500) : text;
    message_return_ = return_page;
    show_page(AppPage::Message);
    bump();
}

// =========================================================== password

lv_subject_t* BaseViewModel::password_mask_subject() { return password_mask_subject_.native(); }
lv_subject_t* BaseViewModel::password_message_subject() { return password_message_subject_.native(); }
lv_subject_t* BaseViewModel::password_busy_subject() { return password_busy_subject_.native(); }

void BaseViewModel::publish_password_mask() {
    const size_t n = std::min(password_input_.size(), kMaskShown);
    password_mask_subject_.set(std::string(n, '*').c_str());
}

void BaseViewModel::password_append(char c) {
    if (password_busy_subject_.value() || password_input_.size() >= kMaxPassword) return;
    password_input_.push_back(c);
    publish_password_mask();
}

void BaseViewModel::password_backspace() {
    if (password_busy_subject_.value() || password_input_.empty()) return;
    password_input_.back() = 0;
    password_input_.pop_back();
    publish_password_mask();
}

void BaseViewModel::password_submit() {
    if (password_busy_subject_.value() || password_input_.empty()) return;
    password_busy_subject_.set(true);
    password_message_subject_.set("Checking...");
    std::string attempt = password_input_;
    wipe(password_input_);
    publish_password_mask();
    auth_future_ = std::async(std::launch::async, [this, attempt]() mutable {
        const bool ok = privilege_.authenticate(attempt);
        wipe(attempt);
        return ok;
    });
}

// =========================================================== selection

void BaseViewModel::move_selection(int delta) {
    if (model_.current_page() == AppPage::Rules) {
        const int n = static_cast<int>(rule_entries_.size());
        rules_index_ = n ? std::clamp(rules_index_ + delta, 0, n - 1) : 0;
    }
    else if (model_.current_page() == AppPage::Ports) {
        const int n = static_cast<int>(port_entries_.size());
        ports_index_ = n ? std::clamp(ports_index_ + delta, 0, n - 1) : 0;
    }
    else if (model_.current_page() == AppPage::Networks) {
        const int n = static_cast<int>(network_entries_.size());
        networks_index_ = n ? std::clamp(networks_index_ + delta, 0, n - 1) : 0;
    }
    bump();
}

// =========================================================== actions -> confirm

void BaseViewModel::open_confirm(PendingChange change) {
    if (service_->busy()) {
        notice("Busy - try again in a moment");
        return;
    }
    if (!loaded_) {
        notice("Firewall state not loaded yet");
        return;
    }
    pending_ = std::move(change);
    if (!pending_.dry_run_args.empty()) {
        pending_.phase = PendingChange::Phase::Checking;
        pending_.request = service_->dry_run(pending_.dry_run_args);
    }
    else {
        pending_.phase = PendingChange::Phase::Ready;
    }
    show_page(AppPage::Confirm);
    bump();
}

void BaseViewModel::toggle_enable() {
    PendingChange c;
    c.return_page = AppPage::Status;
    if (state_.status.active) {
        c.title = "Turn firewall off";
        c.command = "ufw disable";
        c.helper_args = {"disable"};
        c.note = "All ports become reachable. Rules are kept.";
    }
    else {
        c.title = "Turn firewall on";
        c.command = "ufw --force enable";
        c.helper_args = {"enable"};
        fw::Status after = state_.status;
        after.active = true;
        c.note = "Incoming default: " + state_.status.default_in + ".";
        // The helper adds "limit <port>/tcp" for sshd when nothing allows it (SSH exception).
        if (!fw::ssh_guard(state_, after, state_.rules4, state_.rules6).empty()) {
            c.note += " SSH will be allowed (rate-limited) so you are not locked out.";
        }
    }
    open_confirm(std::move(c));
}

void BaseViewModel::toggle_whitelist() {
    const auto* n = current_network();
    if (!n) {
        notice("Not connected to a network");
        return;
    }
    if (n->subnet4.empty()) {
        notice("This network has no IPv4 subnet to whitelist");
        return;
    }
    PendingChange c;
    c.return_page = AppPage::Status;
    const std::string where = n->iface + " " + n->subnet4 +
                              (n->gateway.empty() ? std::string(" (no gateway)")
                                                  : " via " + n->gateway +
                                                        (n->gw_mac.empty() ? "" : " " + n->gw_mac));
    if (fw::is_whitelisted(*n, state_.whitelist)) {
        c.title = "Remove network from whitelist";
        c.command = where;
        c.helper_args = {"whitelist-remove", n->key(), n->subnet4};
        c.note = "\"Whitelisted only\" My network rules stop applying here.";
        // rules from whitelisted-only templates for this network go away
        auto after4 = state_.rules4;
        auto after6 = state_.rules6;
        for (const auto& t : state_.templates) {
            if (t.scope != "whitelisted") continue;
            after4 = without_template(after4, t.id);
            after6 = without_template(after6, t.id);
        }
        c.warning = fw::ssh_guard(state_, state_.status, after4, after6);
    }
    else {
        c.title = "Whitelist this network";
        c.command = where;
        c.helper_args = {"whitelist-add", n->key(), n->subnet4, n->iface + " " + n->subnet4};
        c.note = "\"Whitelisted only\" My network rules will apply here. A gateway MAC can be "
                 "copied, so this is a convenience, not strong security.";
        for (const auto& t : state_.templates) {
            if (t.scope == "whitelisted") c.offer_nm_hook = true;
        }
    }
    open_confirm(std::move(c));
}

void BaseViewModel::undo() {
    if (state_.backups <= 0) {
        notice("Nothing to undo");
        return;
    }
    PendingChange c;
    c.return_page = AppPage::Status;
    c.title = "Undo last change";
    c.command = "restore rules from before the last change";
    c.helper_args = {"undo"};
    c.note = "Cannot be previewed. Does not turn the firewall on or off. " +
             std::to_string(state_.backups) + " change(s) can be undone.";
    open_confirm(std::move(c));
}

void BaseViewModel::delete_selected_rule() {
    if (rules_index_ < 0 || rules_index_ >= static_cast<int>(rule_entries_.size())) return;
    const auto& e = rule_entries_[rules_index_];
    PendingChange c;
    c.return_page = AppPage::Rules;
    c.title = "Delete rule";
    c.command = e.text;
    if (e.is_template) {
        c.helper_args = {"mynet-delete", std::to_string(e.template_id)};
        c.note = "Removes this My network rule on every network.";
        c.warning = fw::ssh_guard(state_, state_.status,
                                  without_template(state_.rules4, e.template_id),
                                  without_template(state_.rules6, e.template_id));
    }
    else {
        c.helper_args = {"delete", e.v6 ? "6" : "4", e.raw};
        c.warning = fw::ssh_guard(state_, state_.status,
                                  e.v6 ? state_.rules4 : without_raw(state_.rules4, e.raw),
                                  e.v6 ? without_raw(state_.rules6, e.raw) : state_.rules6);
    }
    open_confirm(std::move(c));
}

void BaseViewModel::remove_selected_network() {
    if (networks_index_ < 0 || networks_index_ >= static_cast<int>(network_entries_.size())) return;
    const auto& e = network_entries_[networks_index_];
    if (e.current) {
        toggle_whitelist();
        if (model_.current_page() == AppPage::Confirm) pending_.return_page = AppPage::Networks;
        return;
    }
    PendingChange c;
    c.return_page = AppPage::Networks;
    c.title = "Remove network from whitelist";
    c.command = e.text;
    c.helper_args = {"whitelist-remove", e.key, e.subnet4};
    open_confirm(std::move(c));
}

void BaseViewModel::toggle_selected_port() {
    if (ports_index_ < 0 || ports_index_ >= static_cast<int>(port_entries_.size())) return;
    const auto& e = port_entries_[ports_index_];
    if (e.local_only) {
        notice("Only listens on this device; the firewall does not apply");
        return;
    }
    if (service_->busy()) {
        notice("Busy - try again in a moment");
        return;
    }
    const auto target = fw::next_port_state(e.state);
    const char* word = target == fw::PortState::Blocked ? "blocked"
                       : target == fw::PortState::Lan   ? "lan"
                                                        : "allowed";
    PendingChange c;
    c.return_page = AppPage::Ports;
    c.title = e.proto + " " + std::to_string(e.port) + ": " + fw::port_state_label(target);
    c.command = "port " + std::to_string(e.port) + "/" + e.proto + " -> " + fw::port_state_label(target);
    c.helper_args = {"port-set", std::to_string(e.port), e.proto, word};
    std::vector<fw::Rule> after4, after6;
    fw::simulate_port_set(state_, e.proto, e.port, target, after4, after6);
    c.warning = fw::ssh_guard(state_, state_.status, after4, after6);
    if (!c.warning.empty()) {
        if (target == fw::PortState::Lan && !current_network_whitelisted()) {
            c.note = "LAN means My network (whitelisted only), and this network is not whitelisted.";
        }
        open_confirm(std::move(c)); // only lockouts need confirming
        return;
    }
    // instant: apply now, toast on success (U undoes)
    pending_ = std::move(c);
    pending_.request = service_->apply(pending_.helper_args);
    pending_.phase = PendingChange::Phase::Applying;
    bump();
}

// =========================================================== add-rule form

const char* BaseViewModel::form_field_label(int field) {
    switch (static_cast<FormField>(field)) {
        case FormField::Action: return "Action";
        case FormField::Direction: return "Direction";
        case FormField::Port: return "Port";
        case FormField::Proto: return "Protocol";
        case FormField::Source: return "From";
        case FormField::CustomSource: return "Address";
        case FormField::Comment: return "Comment";
        default: return "";
    }
}

std::string BaseViewModel::form_field_value(int field) const {
    switch (static_cast<FormField>(field)) {
        case FormField::Action: return form_.action;
        case FormField::Direction: return form_.direction;
        case FormField::Port: return form_.port;
        case FormField::Proto: return form_.proto;
        case FormField::Source:
            switch (form_.source) {
                case fw::RuleForm::Source::Any: return "any";
                case fw::RuleForm::Source::MyNetWhitelisted: return "My network (whitelisted)";
                case fw::RuleForm::Source::MyNetAny: return "My network (any network)";
                case fw::RuleForm::Source::Custom: return "address...";
            }
            return "";
        case FormField::CustomSource: return form_.custom_source;
        case FormField::Comment: return form_.comment;
        default: return "";
    }
}

bool BaseViewModel::form_field_editable(int field) const {
    const auto f = static_cast<FormField>(field);
    return f == FormField::Port || f == FormField::CustomSource || f == FormField::Comment;
}

bool BaseViewModel::form_field_visible(int field) const {
    if (static_cast<FormField>(field) == FormField::CustomSource) {
        return form_.source == fw::RuleForm::Source::Custom;
    }
    return field >= 0 && field < static_cast<int>(FormField::Count);
}

void BaseViewModel::open_add_rule() {
    form_ = fw::RuleForm{};
    form_field_ = static_cast<int>(FormField::Port);
    form_error_.clear();
    show_page(AppPage::AddRule);
    bump();
}

void BaseViewModel::form_move(int delta) {
    const int count = static_cast<int>(FormField::Count);
    int f = form_field_;
    do {
        f = ((f + delta) % count + count) % count;
    } while (!form_field_visible(f));
    form_field_ = f;
    bump();
}

void BaseViewModel::form_cycle(int delta) {
    switch (static_cast<FormField>(form_field_)) {
        case FormField::Action:
            form_.action = cycle(kActions, form_.action, delta);
            break;
        case FormField::Direction:
            form_.direction = form_.direction == "in" ? "out" : "in";
            break;
        case FormField::Proto:
            form_.proto = cycle(kProtos, form_.proto, delta);
            break;
        case FormField::Source: {
            const int n = 4;
            int s = static_cast<int>(form_.source);
            s = ((s + delta) % n + n) % n;
            form_.source = static_cast<fw::RuleForm::Source>(s);
            break;
        }
        default:
            return;
    }
    form_error_.clear();
    bump();
}

void BaseViewModel::form_type(char c) {
    std::string* target = nullptr;
    switch (static_cast<FormField>(form_field_)) {
        case FormField::Port:
            if (!((c >= '0' && c <= '9') || c == ':' || c == ',')) return;
            target = &form_.port;
            break;
        case FormField::CustomSource:
            if (!(std::isxdigit(static_cast<unsigned char>(c)) || c == '.' || c == ':' || c == '/')) return;
            target = &form_.custom_source;
            break;
        case FormField::Comment:
            if (c == '\'' || c == '"') return;
            target = &form_.comment;
            break;
        default:
            return;
    }
    if (target->size() >= 60) return;
    target->push_back(c);
    form_error_.clear();
    bump();
}

void BaseViewModel::form_backspace() {
    std::string* target = nullptr;
    switch (static_cast<FormField>(form_field_)) {
        case FormField::Port: target = &form_.port; break;
        case FormField::CustomSource: target = &form_.custom_source; break;
        case FormField::Comment: target = &form_.comment; break;
        default: return;
    }
    if (!target->empty()) target->pop_back();
    bump();
}

void BaseViewModel::form_apply_preset(int index) {
    const auto& list = fw::presets();
    if (index < 0 || index >= static_cast<int>(list.size())) return;
    const auto& p = list[index];
    form_.action = p.action;
    form_.direction = "in";
    form_.port = p.port;
    form_.proto = p.proto;
    form_.comment = p.label;
    form_error_.clear();
    bump();
}

void BaseViewModel::form_submit() {
    form_error_ = fw::validate_form(form_);
    if (!form_error_.empty()) {
        bump();
        return;
    }
    PendingChange c;
    c.return_page = AppPage::Rules;
    c.title = "Add rule";
    if (form_.is_mynet()) {
        auto t = fw::form_template(form_);
        c.command = fw::describe_template(t);
        c.helper_args = {"mynet-add", t.action, t.proto, t.port, t.scope};
        c.offer_nm_hook = t.scope == "whitelisted";
        if (!t.comment.empty()) c.helper_args.push_back(t.comment);
        // simulate the live rules this would add right now
        auto after4 = state_.rules4;
        auto after6 = state_.rules6;
        t.id = 1 << 20;
        for (const auto& n : state_.networks) {
            if (t.scope == "whitelisted" && !fw::is_whitelisted(n, state_.whitelist)) continue;
            for (const auto& subnet : {n.subnet4, n.subnet6}) {
                if (subnet.empty()) continue;
                fw::Rule r;
                r.action = t.action;
                r.proto = t.proto;
                r.dport = t.port;
                r.dst = fw::Cidr::parse(subnet).v6 ? "::/0" : "0.0.0.0/0";
                r.sport = "any";
                r.src = subnet;
                r.direction = "in";
                r.v6 = fw::Cidr::parse(subnet).v6;
                (r.v6 ? after6 : after4).push_back(r);
            }
        }
        c.warning = fw::ssh_guard(state_, state_.status, after4, after6);
        const auto* n = current_network();
        const bool applies_now = n && (t.scope == "any" || fw::is_whitelisted(*n, state_.whitelist));
        c.note = applies_now ? "Applies now, from " + (n->subnet4.empty() ? n->subnet6 : n->subnet4) + "."
                             : "Not active on this network (it is not whitelisted).";
    }
    else {
        const auto args = fw::form_args(form_);
        c.command = "ufw " + fw::join_args(args);
        c.dry_run_args = args;
        c.helper_args = {"add"};
        c.helper_args.insert(c.helper_args.end(), args.begin(), args.end());
    }
    open_confirm(std::move(c));
}

// =========================================================== free-form

void BaseViewModel::open_freeform() {
    freeform_text_.clear();
    freeform_error_.clear();
    show_page(AppPage::FreeForm);
    bump();
}

void BaseViewModel::freeform_type(char c) {
    if (freeform_text_.size() >= kMaxText) return;
    freeform_text_.push_back(c);
    freeform_error_.clear();
    bump();
}

void BaseViewModel::freeform_backspace() {
    if (!freeform_text_.empty()) freeform_text_.pop_back();
    bump();
}

void BaseViewModel::freeform_submit() {
    std::vector<std::string> args;
    freeform_error_ = fw::validate_freeform(freeform_text_, args);
    if (!freeform_error_.empty()) {
        bump();
        return;
    }
    PendingChange c;
    c.return_page = AppPage::Rules;
    c.title = "Add rule";
    c.command = "ufw " + fw::join_args(args);
    c.dry_run_args = args;
    c.helper_args = {"add"};
    c.helper_args.insert(c.helper_args.end(), args.begin(), args.end());
    open_confirm(std::move(c));
}

// =========================================================== confirm

void BaseViewModel::finish_dry_run(const FirewallService::Result& result) {
    if (!result.ok || result.output.find("ERROR") != std::string::npos) {
        pending_.phase = PendingChange::Phase::Error;
        pending_.note = error_lines(result.output);
        return;
    }
    std::vector<fw::Rule> after4, after6;
    fw::parse_dry_run(result.output, after4, after6);
    // a family missing from the dry-run output is unchanged
    if (result.output.find(":ufw-user-input") == std::string::npos) after4 = state_.rules4;
    if (result.output.find(":ufw6-user-input") == std::string::npos) after6 = state_.rules6;
    pending_.warning = fw::ssh_guard(state_, state_.status, after4, after6);
    if (result.output.find("Skipping") != std::string::npos) {
        pending_.note = "This rule already exists; applying changes nothing.";
    }
    else {
        pending_.note = "Checked with ufw --dry-run.";
    }
    pending_.phase = PendingChange::Phase::Ready;
}

void BaseViewModel::confirm_accept() {
    if (pending_.phase != PendingChange::Phase::Ready) return;
    if (!pending_.warning.empty() && !pending_.acknowledged) {
        pending_.acknowledged = true;
        bump();
        return;
    }
    const auto id = service_->apply(pending_.helper_args);
    if (!id) {
        notice("Busy - try again in a moment");
        return;
    }
    pending_.request = id;
    pending_.phase = PendingChange::Phase::Applying;
    bump();
}

void BaseViewModel::finish_apply(const FirewallService::Result& result) {
    const auto back_to = pending_.return_page;
    if (result.ok) {
        notice(pending_.title + (back_to == AppPage::Ports ? "  (U undo)" : ": done"));
        const bool offer = pending_.offer_nm_hook;
        pending_ = PendingChange{};
        if (offer && should_offer_nm_hook()) {
            offer_nm_hook(back_to);
            return;
        }
        show_page(back_to);
    }
    else {
        const auto title = pending_.title + " failed";
        pending_ = PendingChange{};
        show_message(title, result.output.empty() ? "ipdoit-helper failed" : result.output,
                     back_to);
    }
}

// "Whitelisted only" rules only follow the network if something re-syncs them when it
// changes. Offer the NetworkManager hook right after a change that relies on it.
bool BaseViewModel::should_offer_nm_hook() const {
    return state_.nm_hook == 0 && !nm_hook_declined_;
}

void BaseViewModel::offer_nm_hook(AppPage return_page) {
    PendingChange c;
    c.return_page = return_page;
    c.is_nm_hook_offer = true;
    c.title = "Follow network changes?";
    c.command = "link nm-dispatcher into\n/etc/NetworkManager/dispatcher.d";
    c.helper_args = {"nm-hook-on"};
    c.note = "\"Whitelisted only\" rules are only updated while Ipdoit is open. If you leave "
             "this network, they stay open until you open Ipdoit again. Enter lets "
             "NetworkManager re-sync them on every network change. Esc: not now.";
    open_confirm(std::move(c));
}

} // namespace viewmodel
