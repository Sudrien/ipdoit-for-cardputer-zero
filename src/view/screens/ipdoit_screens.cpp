/*
 * SPDX-License-Identifier: MIT
 */

#include "ipdoit_screens.h"

#include "screen_style.h"

#include <cstdio>

namespace screen {
namespace {

using viewmodel::BaseViewModel;
using Field = BaseViewModel::FormField;

constexpr int kToneNormal = 0;
constexpr int kToneGood = 1;
constexpr int kToneBad = 2;
constexpr int kToneWarn = 3;
constexpr int kToneMuted = 4;

bool is_up(uint32_t key) { return key == LV_KEY_UP || key == ';'; }
bool is_down(uint32_t key) { return key == LV_KEY_DOWN || key == '.'; }
bool is_left(uint32_t key) { return key == LV_KEY_LEFT || key == ','; }
bool is_right(uint32_t key) { return key == LV_KEY_RIGHT || key == '/'; }
bool is_delete(uint32_t key) {
    return key == 'd' || key == 'D' || key == LV_KEY_DEL || key == LV_KEY_BACKSPACE;
}

int verdict_tone(fw::Verdict v) {
    switch (v) {
        case fw::Verdict::Allowed:
        case fw::Verdict::Limited:
        case fw::Verdict::FirewallOff:
            return kToneWarn; // reachable from anywhere
        case fw::Verdict::LanOnly:
        case fw::Verdict::Partial:
            return kToneNormal;
        case fw::Verdict::Blocked:
        case fw::Verdict::LocalOnly:
            return kToneGood;
        default:
            return kToneMuted;
    }
}

} // namespace

// ============================================================ IpdoitScreen

IpdoitScreen::IpdoitScreen(viewmodel::BaseViewModel& view_model, app::AssetManager& assets)
    : BaseScreen(view_model, assets) {}

void IpdoitScreen::build_content(lv_obj_t* content) {
    auto* column = style::box(content);
    lv_obj_set_size(column, LV_PCT(100), LV_PCT(100));
    lv_obj_set_flex_flow(column, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_hor(column, 8, 0);
    lv_obj_set_style_pad_top(column, 3, 0);
    lv_obj_set_style_pad_row(column, 2, 0);
    build(column);
    reactive::observe_obj(column, view_model().revision_subject(), revision_cb, this);
    reactive::observe_obj(column, view_model().dark_mode_subject(), revision_cb, this);
}

void IpdoitScreen::revision_cb(lv_observer_t* observer, lv_subject_t*) {
    auto* self = static_cast<IpdoitScreen*>(lv_observer_get_user_data(observer));
    if (self) self->refresh();
}

lv_obj_t* IpdoitScreen::make_label(lv_obj_t* parent, uint32_t size, bool bold, const char* text) {
    auto* l = lv_label_create(parent);
    lv_label_set_text(l, text);
    lv_obj_set_style_text_font(l, style::font(assets(), size, bold), 0);
    set_tone(l, kToneNormal);
    return l;
}

void IpdoitScreen::set_tone(lv_obj_t* label, int tone) {
    const auto p = view::palette(view_model().is_dark_mode());
    lv_color_t c = p.text;
    switch (tone) {
        case kToneGood: c = p.success; break;
        case kToneBad: c = p.error; break;
        case kToneWarn: c = p.warning; break;
        case kToneMuted: c = p.text_disabled; break;
        case 5: c = p.primary; break;
        default: break;
    }
    lv_obj_set_style_text_color(label, c, 0);
}

void IpdoitScreen::set_muted(lv_obj_t* label) {
    set_tone(label, kToneMuted);
}

lv_obj_t* IpdoitScreen::make_list(lv_obj_t* parent) {
    auto* list = lv_obj_create(parent);
    lv_obj_remove_style_all(list);
    lv_obj_set_width(list, LV_PCT(100));
    lv_obj_set_flex_grow(list, 1);
    lv_obj_set_flex_flow(list, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_scroll_dir(list, LV_DIR_VER);
    lv_obj_set_scrollbar_mode(list, LV_SCROLLBAR_MODE_AUTO);
    return list;
}

void IpdoitScreen::fill_list(lv_obj_t* list, const std::vector<std::string>& rows, int selected,
                             const std::vector<int>& tones, const std::vector<int>& columns) {
    lv_obj_clean(list);
    const auto p = view::palette(view_model().is_dark_mode());
    lv_obj_t* selected_row = nullptr;
    for (size_t i = 0; i < rows.size(); ++i) {
        auto* row = style::box(list);
        lv_obj_set_size(row, LV_PCT(100), 17);
        lv_obj_set_style_radius(row, 3, 0);
        lv_obj_set_style_pad_hor(row, 4, 0);
        if (static_cast<int>(i) == selected) {
            lv_obj_set_style_bg_color(row, p.primary, 0);
            lv_obj_set_style_bg_opa(row, LV_OPA_20, 0);
            selected_row = row;
        }
        // split into columns
        std::vector<std::string> cells;
        size_t start = 0;
        while (true) {
            const auto tab = rows[i].find('\t', start);
            cells.push_back(rows[i].substr(start, tab == std::string::npos ? std::string::npos
                                                                           : tab - start));
            if (tab == std::string::npos || cells.size() >= columns.size()) break;
            start = tab + 1;
        }
        for (size_t c = 0; c < cells.size(); ++c) {
            const int x = c < columns.size() ? columns[c] : 0;
            const int next = c + 1 < cells.size() && c + 1 < columns.size() ? columns[c + 1] : 304;
            auto* l = make_label(row, 12, false, cells[c].c_str());
            lv_obj_set_size(l, next - x - 4, 15);
            lv_label_set_long_mode(l, LV_LABEL_LONG_MODE_DOTS);
            lv_obj_align(l, LV_ALIGN_LEFT_MID, x, 1);
            set_tone(l, i < tones.size() ? tones[i] : kToneNormal);
        }
    }
    if (selected_row) {
        lv_obj_update_layout(list);
        lv_obj_scroll_to_view(selected_row, LV_ANIM_OFF);
    }
}

bool IpdoitScreen::handle_main_keys(uint32_t key) {
    auto& vm = view_model();
    if (is_left(key)) {
        vm.next_page(-1);
        return true;
    }
    if (is_right(key)) {
        vm.next_page(1);
        return true;
    }
    if (key == 'r' || key == 'R') {
        vm.refresh();
        return true;
    }
    if (key == LV_KEY_ESC) {
        vm.back();
        return true;
    }
    return false;
}

// ============================================================ Status

void StatusScreen::build(lv_obj_t* column) {
    state_ = make_label(column, 20, true);
    defaults_ = make_label(column, 12);
    network_ = make_label(column, 12);
    lv_obj_set_width(network_, LV_PCT(100));
    lv_label_set_long_mode(network_, LV_LABEL_LONG_MODE_DOTS);
    counts_ = make_label(column, 12);
    info_ = make_label(column, 12);
    lv_obj_set_width(info_, LV_PCT(100));
    lv_label_set_long_mode(info_, LV_LABEL_LONG_MODE_DOTS);
    refresh();
}

void StatusScreen::refresh() {
    auto& vm = view_model();
    const auto& st = vm.state();
    if (!vm.loaded()) {
        lv_label_set_text(state_, "Firewall ...");
        set_tone(state_, kToneMuted);
        lv_label_set_text(defaults_, vm.load_error().empty() ? "Reading firewall state..."
                                                              : vm.load_error().c_str());
        lv_label_set_text(network_, "");
        lv_label_set_text(counts_, "");
        lv_label_set_text(info_, "");
        return;
    }
    lv_label_set_text(state_, st.status.active ? "Firewall ON" : "Firewall OFF");
    set_tone(state_, st.status.active ? kToneGood : kToneBad);

    char buf[160];
    std::snprintf(buf, sizeof(buf), "In: %s   Out: %s   Routed: %s",
                  st.status.default_in.c_str(), st.status.default_out.c_str(),
                  st.status.default_routed.c_str());
    lv_label_set_text(defaults_, buf);

    if (const auto* n = vm.current_network()) {
        std::snprintf(buf, sizeof(buf), "%s %s  %s", n->iface.c_str(),
                      (n->subnet4.empty() ? n->subnet6 : n->subnet4).c_str(),
                      vm.current_network_whitelisted() ? "whitelisted" : "not whitelisted");
        lv_label_set_text(network_, buf);
        set_tone(network_, vm.current_network_whitelisted() ? kToneGood : kToneNormal);
    }
    else {
        lv_label_set_text(network_, "No network");
        set_muted(network_);
    }

    int reachable = 0;
    for (const auto& r : vm.port_rows()) {
        if (r.v4 == fw::Verdict::Allowed || r.v4 == fw::Verdict::Limited ||
            r.v4 == fw::Verdict::FirewallOff || r.v6 == fw::Verdict::Allowed ||
            r.v6 == fw::Verdict::Limited || r.v6 == fw::Verdict::FirewallOff) {
            ++reachable;
        }
    }
    std::snprintf(buf, sizeof(buf), "%zu rules   %zu ports, %d open to all   %d undo",
                  vm.rule_entries().size(), vm.port_rows().size(), reachable, st.backups);
    lv_label_set_text(counts_, buf);
    set_muted(counts_);

    lv_label_set_text(info_, vm.busy() ? "Working..." : (vm.load_error().empty() ? "" : vm.load_error().c_str()));
    set_tone(info_, vm.load_error().empty() ? kToneMuted : kToneBad);
}

bool StatusScreen::handle_key(uint32_t key) {
    auto& vm = view_model();
    switch (key) {
        case 'e':
        case 'E':
            vm.toggle_enable();
            return true;
        case 'w':
        case 'W':
            vm.toggle_whitelist();
            return true;
        case 'u':
        case 'U':
            vm.undo();
            return true;
        default:
            return handle_main_keys(key);
    }
}

// ============================================================ Rules

void RulesScreen::build(lv_obj_t* column) {
    header_ = make_label(column, 12);
    list_ = make_list(column);
    refresh();
}

void RulesScreen::refresh() {
    auto& vm = view_model();
    const auto& entries = vm.rule_entries();
    char buf[96];
    std::snprintf(buf, sizeof(buf), "%zu rules, first match wins%s", entries.size(),
                  vm.busy() ? "  (working...)" : "");
    lv_label_set_text(header_, buf);
    set_muted(header_);
    std::vector<std::string> rows;
    std::vector<int> tones;
    for (size_t i = 0; i < entries.size(); ++i) {
        rows.push_back(std::to_string(i + 1) + "  " + entries[i].text);
        tones.push_back(entries[i].is_template ? 5 : kToneNormal);
    }
    if (rows.empty()) {
        rows.push_back("No rules. Press A to add one.");
        tones.push_back(kToneMuted);
    }
    fill_list(list_, rows, entries.empty() ? -1 : vm.rules_index(), tones);
}

bool RulesScreen::handle_key(uint32_t key) {
    auto& vm = view_model();
    if (is_up(key)) {
        vm.move_selection(-1);
        return true;
    }
    if (is_down(key)) {
        vm.move_selection(1);
        return true;
    }
    if (is_delete(key)) {
        vm.delete_selected_rule();
        return true;
    }
    if (key == 'a' || key == 'A' || key == LV_KEY_ENTER) {
        vm.open_add_rule();
        return true;
    }
    if (key == 'f' || key == 'F') {
        vm.open_freeform();
        return true;
    }
    return handle_main_keys(key);
}

// ============================================================ Ports

void PortsScreen::build(lv_obj_t* column) {
    header_ = make_label(column, 12);
    list_ = make_list(column);
    refresh();
}

void PortsScreen::refresh() {
    auto& vm = view_model();
    lv_label_set_text(header_, "Listening ports (ufw rules only)");
    set_muted(header_);
    std::vector<std::string> rows;
    std::vector<int> tones;
    for (const auto& r : vm.port_rows()) {
        rows.push_back(r.proto + " " + std::to_string(r.port) + "\t" +
                       (r.process.empty() ? std::string("?") : r.process) + "\t" + r.summary());
        const auto worst = r.v6 == fw::Verdict::NotApplicable ? r.v4 : r.v6;
        tones.push_back(verdict_tone(r.v4 == fw::Verdict::NotApplicable ? worst : r.v4));
    }
    if (rows.empty()) {
        rows.push_back(vm.loaded() ? "Nothing is listening." : "Reading...");
        tones.push_back(kToneMuted);
    }
    fill_list(list_, rows, -1, tones, {0, 70, 160});
}

bool PortsScreen::handle_key(uint32_t key) {
    if (is_up(key)) {
        lv_obj_scroll_by_bounded(list_, 0, 34, LV_ANIM_OFF);
        return true;
    }
    if (is_down(key)) {
        lv_obj_scroll_by_bounded(list_, 0, -34, LV_ANIM_OFF);
        return true;
    }
    return handle_main_keys(key);
}

// ============================================================ Networks

void NetworksScreen::build(lv_obj_t* column) {
    header_ = make_label(column, 12);
    list_ = make_list(column);
    refresh();
}

void NetworksScreen::refresh() {
    auto& vm = view_model();
    lv_label_set_text(header_, "Current network, then whitelist");
    set_muted(header_);
    std::vector<std::string> rows;
    std::vector<int> tones;
    for (const auto& e : vm.network_entries()) {
        rows.push_back((e.current ? "> " : "  ") + e.text);
        tones.push_back(e.whitelisted ? kToneGood : kToneNormal);
    }
    if (rows.empty()) {
        rows.push_back("No network and nothing whitelisted.");
        tones.push_back(kToneMuted);
    }
    fill_list(list_, rows, vm.network_entries().empty() ? -1 : vm.networks_index(), tones);
}

bool NetworksScreen::handle_key(uint32_t key) {
    auto& vm = view_model();
    if (is_up(key)) {
        vm.move_selection(-1);
        return true;
    }
    if (is_down(key)) {
        vm.move_selection(1);
        return true;
    }
    if (is_delete(key) || key == LV_KEY_ENTER) {
        vm.remove_selected_network(); // on the current network: whitelist toggle
        return true;
    }
    return handle_main_keys(key);
}

// ============================================================ Add rule

void AddRuleScreen::build(lv_obj_t* column) {
    list_ = make_list(column);
    footer_ = make_label(column, 10);
    lv_obj_set_size(footer_, LV_PCT(100), 13); // one line; DOTS needs a fixed height
    lv_label_set_long_mode(footer_, LV_LABEL_LONG_MODE_DOTS);
    refresh();
}

void AddRuleScreen::refresh() {
    auto& vm = view_model();
    std::vector<std::string> rows;
    std::vector<int> tones;
    int selected = -1;
    for (int f = 0; f < static_cast<int>(Field::Count); ++f) {
        if (!vm.form_field_visible(f)) continue;
        const bool focus = f == vm.form_field();
        if (focus) selected = static_cast<int>(rows.size());
        std::string value = vm.form_field_value(f);
        if (vm.form_field_editable(f)) {
            value += focus ? "_" : "";
            if (value.empty()) value = "-";
        }
        else {
            value = "< " + value + " >";
        }
        rows.push_back(std::string(BaseViewModel::form_field_label(f)) + "\t" + value);
        tones.push_back(kToneNormal);
    }
    fill_list(list_, rows, selected, tones, {0, 74});
    if (!vm.form_error().empty()) {
        lv_label_set_text(footer_, vm.form_error().c_str());
        set_tone(footer_, kToneBad);
    }
    else {
        lv_label_set_text(footer_, "Presets on a < > field: 1 SSH 2 HTTP 3 HTTPS 4 DNS 5 mDNS");
        set_muted(footer_);
    }
}

bool AddRuleScreen::handle_key(uint32_t key) {
    auto& vm = view_model();
    const bool text_field = vm.form_field_editable(vm.form_field());
    switch (key) {
        case LV_KEY_UP:
            vm.form_move(-1);
            return true;
        case LV_KEY_DOWN:
            vm.form_move(1);
            return true;
        case LV_KEY_LEFT:
            vm.form_cycle(-1);
            return true;
        case LV_KEY_RIGHT:
            vm.form_cycle(1);
            return true;
        case LV_KEY_ENTER:
            vm.form_submit();
            return true;
        case LV_KEY_ESC:
            vm.back();
            return true;
        case LV_KEY_BACKSPACE:
            vm.form_backspace();
            return true;
        default:
            break;
    }
    if (!text_field) {
        // Cardputer arrows without fn, and presets
        if (key == ';') { vm.form_move(-1); return true; }
        if (key == '.') { vm.form_move(1); return true; }
        if (key == ',') { vm.form_cycle(-1); return true; }
        if (key == '/' || key == ' ') { vm.form_cycle(1); return true; }
        if (key >= '1' && key <= '5') { vm.form_apply_preset(static_cast<int>(key - '1')); return true; }
        return true;
    }
    if (key >= 32 && key <= 126) {
        vm.form_type(static_cast<char>(key));
    }
    return true;
}

// ============================================================ Free-form

void FreeFormScreen::build(lv_obj_t* column) {
    auto* hint = make_label(column, 12, false, "Type a ufw rule (allow/deny/reject/limit):");
    set_muted(hint);
    field_ = style::box(column);
    lv_obj_set_size(field_, LV_PCT(100), 40);
    lv_obj_set_style_border_width(field_, 2, 0);
    lv_obj_set_style_radius(field_, 5, 0);
    lv_obj_set_style_pad_all(field_, 4, 0);
    style::accent(field_, view_model().dark_mode_subject(), style::Accent::Part::Border,
                  style::Accent::Tone::Primary);
    text_ = make_label(field_, 12, true);
    lv_obj_set_width(text_, LV_PCT(100));
    lv_label_set_long_mode(text_, LV_LABEL_LONG_MODE_WRAP);
    footer_ = make_label(column, 10);
    lv_obj_set_width(footer_, LV_PCT(100));
    lv_label_set_long_mode(footer_, LV_LABEL_LONG_MODE_WRAP);
    refresh();
}

void FreeFormScreen::refresh() {
    auto& vm = view_model();
    lv_label_set_text(text_, ("ufw " + vm.freeform_text() + "_").c_str());
    if (!vm.freeform_error().empty()) {
        lv_label_set_text(footer_, vm.freeform_error().c_str());
        set_tone(footer_, kToneBad);
    }
    else {
        lv_label_set_text(footer_, "e.g. allow from 192.168.1.0/24 to any port 22 proto tcp");
        set_muted(footer_);
    }
}

bool FreeFormScreen::handle_key(uint32_t key) {
    auto& vm = view_model();
    switch (key) {
        case LV_KEY_ENTER: vm.freeform_submit(); return true;
        case LV_KEY_ESC: vm.back(); return true;
        case LV_KEY_BACKSPACE: vm.freeform_backspace(); return true;
        default: break;
    }
    if (key >= 32 && key <= 126) {
        vm.freeform_type(static_cast<char>(key));
    }
    return true;
}

// ============================================================ Confirm

void ConfirmScreen::build(lv_obj_t* column) {
    title_ = make_label(column, 14, true);
    scroller_ = make_list(column);
    command_ = make_label(scroller_, 12, true);
    note_ = make_label(scroller_, 12);
    warning_ = make_label(scroller_, 12, true);
    for (auto* l : {command_, note_, warning_}) {
        lv_obj_set_width(l, LV_PCT(100));
        lv_label_set_long_mode(l, LV_LABEL_LONG_MODE_WRAP);
    }
    phase_ = make_label(column, 12, true);
    refresh();
}

void ConfirmScreen::refresh() {
    auto& vm = view_model();
    const auto& p = vm.pending();
    lv_label_set_text(title_, p.title.c_str());
    lv_label_set_text(command_, p.command.c_str());
    set_tone(command_, 5);
    lv_label_set_text(note_, p.note.c_str());
    set_tone(note_, p.phase == viewmodel::PendingChange::Phase::Error ? kToneBad : kToneMuted);
    if (p.warning.empty()) {
        lv_obj_add_flag(warning_, LV_OBJ_FLAG_HIDDEN);
    }
    else {
        lv_obj_remove_flag(warning_, LV_OBJ_FLAG_HIDDEN);
        lv_label_set_text(warning_, ("Warning: " + p.warning).c_str());
        set_tone(warning_, kToneBad);
    }
    const char* phase = "";
    int tone = kToneNormal;
    switch (p.phase) {
        case viewmodel::PendingChange::Phase::Checking:
            phase = "Checking with ufw --dry-run...";
            tone = kToneMuted;
            break;
        case viewmodel::PendingChange::Phase::Ready:
            if (!p.warning.empty() && p.acknowledged) {
                phase = "Press Enter again to apply anyway";
                tone = kToneBad;
            }
            else {
                phase = "Enter: apply    Esc: cancel";
                tone = kToneGood;
            }
            break;
        case viewmodel::PendingChange::Phase::Applying:
            phase = "Applying...";
            tone = kToneMuted;
            break;
        case viewmodel::PendingChange::Phase::Error:
            phase = "ufw rejected this. Esc: back";
            tone = kToneBad;
            break;
    }
    lv_label_set_text(phase_, phase);
    set_tone(phase_, tone);
}

bool ConfirmScreen::handle_key(uint32_t key) {
    auto& vm = view_model();
    if (key == LV_KEY_ENTER) {
        vm.confirm_accept();
        return true;
    }
    if (key == LV_KEY_ESC) {
        vm.back();
        return true;
    }
    if (is_up(key)) {
        lv_obj_scroll_by_bounded(scroller_, 0, 30, LV_ANIM_OFF);
        return true;
    }
    if (is_down(key)) {
        lv_obj_scroll_by_bounded(scroller_, 0, -30, LV_ANIM_OFF);
        return true;
    }
    return true;
}

// ============================================================ Message

void MessageScreen::build(lv_obj_t* column) {
    title_ = make_label(column, 14, true);
    scroller_ = make_list(column);
    text_ = make_label(scroller_, 12);
    lv_obj_set_width(text_, LV_PCT(100));
    lv_label_set_long_mode(text_, LV_LABEL_LONG_MODE_WRAP);
    refresh();
}

void MessageScreen::refresh() {
    auto& vm = view_model();
    lv_label_set_text(title_, vm.message_title().c_str());
    set_tone(title_, kToneBad);
    lv_label_set_text(text_, vm.message_text().c_str());
}

bool MessageScreen::handle_key(uint32_t key) {
    auto& vm = view_model();
    if (key == LV_KEY_ENTER || key == LV_KEY_ESC) {
        vm.back();
        return true;
    }
    if (is_up(key)) {
        lv_obj_scroll_by_bounded(scroller_, 0, 30, LV_ANIM_OFF);
        return true;
    }
    if (is_down(key)) {
        lv_obj_scroll_by_bounded(scroller_, 0, -30, LV_ANIM_OFF);
        return true;
    }
    return true;
}

} // namespace screen
