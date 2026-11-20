/*
 * SPDX-FileCopyrightText: 2026 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */

#include "navbar.h"

#include "asset_manager.h"
#include "bindings.h"
#include "theme.h"

namespace view::widgets {
namespace {

struct Hint {
    const char* key;
    const char* action;
};

using Hints = std::array<Hint, 3>;

Hints hints_for(model::AppPage page) {
    switch (page) {
        case model::AppPage::Password:
            return {{{"ESC", "Quit"}, {"ENTER", "Unlock"}, {nullptr, nullptr}}};
        case model::AppPage::Status:
            return {{{"E", "On/Off"}, {"W", "Whitelist"}, {"U", "Undo"}}};
        case model::AppPage::Rules:
            return {{{"A", "Add"}, {"T", "Type"}, {"D", "Delete"}}};
        case model::AppPage::Ports:
            return {{{"ENTER", "Toggle"}, {"U", "Undo"}, {nullptr, nullptr}}};
        case model::AppPage::Networks:
            return {{{"ENTER", "Toggle"}, {"D", "Remove"}, {nullptr, nullptr}}};
        case model::AppPage::AddRule:
            return {{{"ESC", "Back"}, {"TAB", "Change"}, {"ENTER", "Check"}}};
        case model::AppPage::FreeForm:
            return {{{"ESC", "Back"}, {"ENTER", "Check"}, {nullptr, nullptr}}};
        case model::AppPage::Confirm:
            return {{{"ESC", "Cancel"}, {"ENTER", "Apply"}, {nullptr, nullptr}}};
        case model::AppPage::Message:
            return {{{"ENTER", "Back"}, {nullptr, nullptr}, {nullptr, nullptr}}};
    }
    return {};
}

} // namespace

NavBar::NavBar(lv_obj_t* parent, viewmodel::BaseViewModel& view_model, app::AssetManager& assets)
    : BaseWidgets(parent), view_model_(view_model), assets_(assets) {}

NavBar::~NavBar() = default; // observers are bound to core_obj_ and go with it

void NavBar::build() {
    if (core_obj_) {
        return;
    }

    core_obj_ = lv_obj_create(parent_);
    lv_obj_remove_style_all(core_obj_);
    lv_obj_set_size(core_obj_, LV_PCT(100), kNavBarHeight);
    lv_obj_align(core_obj_, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_clear_flag(core_obj_, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(core_obj_, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(core_obj_, LV_FLEX_ALIGN_SPACE_BETWEEN, LV_FLEX_ALIGN_CENTER,
                          LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_hor(core_obj_, 10, 0);
    reactive::bind_theme(core_obj_, view_model_.dark_mode_subject(), reactive::ThemeRole::Bar);

    const lv_font_t* key_font = assets_.load_standard_font(14);
    const lv_font_t* text_font = assets_.load_standard_font(14, app::StandardFontWeight::Regular);

    // Page indicator on the main pages: red filled triangles like the arrow labels printed
    // on the Z and C keys, then the page number: "<| / |> (3)".
    page_nav_ = lv_obj_create(core_obj_);
    lv_obj_remove_style_all(page_nav_);
    lv_obj_set_size(page_nav_, LV_SIZE_CONTENT, LV_PCT(100));
    lv_obj_set_flex_flow(page_nav_, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(page_nav_, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_column(page_nav_, 3, 0);
    lv_obj_clear_flag(page_nav_, LV_OBJ_FLAG_SCROLLABLE);
    for (int dir = 0; dir < 2; ++dir) {
        if (dir == 1) {
            auto* slash = lv_label_create(page_nav_);
            lv_label_set_text(slash, "/");
            lv_obj_set_style_text_font(slash, text_font ? text_font : &lv_font_montserrat_14, 0);
            reactive::bind_theme(slash, view_model_.dark_mode_subject(), reactive::ThemeRole::Text);
        }
        auto* tri = lv_obj_create(page_nav_);
        lv_obj_remove_style_all(tri);
        lv_obj_set_size(tri, 8, 11);
        lv_obj_add_event_cb(tri, triangle_draw_cb, LV_EVENT_DRAW_MAIN,
                            reinterpret_cast<void*>(static_cast<intptr_t>(dir)));
    }
    page_number_ = lv_label_create(page_nav_);
    lv_obj_set_style_text_font(page_number_, text_font ? text_font : &lv_font_montserrat_14, 0);
    reactive::bind_theme(page_number_, view_model_.dark_mode_subject(), reactive::ThemeRole::Text);

    for (std::size_t i = 0; i < kMaxHints; ++i) {
        auto* item = lv_obj_create(core_obj_);
        lv_obj_remove_style_all(item);
        lv_obj_set_size(item, LV_SIZE_CONTENT, LV_PCT(100));
        lv_obj_set_flex_flow(item, LV_FLEX_FLOW_ROW);
        lv_obj_set_flex_align(item, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER,
                              LV_FLEX_ALIGN_CENTER);
        lv_obj_set_style_pad_column(item, 4, 0);
        lv_obj_clear_flag(item, LV_OBJ_FLAG_SCROLLABLE);

        auto* key = lv_label_create(item);
        lv_obj_set_style_text_font(key, key_font ? key_font : &lv_font_montserrat_14, 0);
        auto* action = lv_label_create(item);
        lv_obj_set_style_text_font(action, text_font ? text_font : &lv_font_montserrat_14, 0);

        items_[i] = item;
        key_labels_[i] = key;
        action_labels_[i] = action;
    }

    reactive::observe_obj(core_obj_, view_model_.current_page_subject(), update_cb, this);
    reactive::observe_obj(core_obj_, view_model_.dark_mode_subject(), update_cb, this);
    update_hints();
}

// Filled red triangle pointing left (user data 0) or right (1).
void NavBar::triangle_draw_cb(lv_event_t* e) {
    auto* obj = static_cast<lv_obj_t*>(lv_event_get_target(e));
    const bool right = reinterpret_cast<intptr_t>(lv_event_get_user_data(e)) != 0;
    lv_area_t a;
    lv_obj_get_coords(obj, &a);
    lv_draw_triangle_dsc_t dsc;
    lv_draw_triangle_dsc_init(&dsc);
    dsc.color = lv_color_hex(0xF0502A); // the orange-red of the key labels
    dsc.opa = LV_OPA_COVER;
    const int32_t mid = (a.y1 + a.y2) / 2;
    if (right) {
        dsc.p[0] = {a.x1, a.y1};
        dsc.p[1] = {a.x1, a.y2};
        dsc.p[2] = {a.x2, mid};
    }
    else {
        dsc.p[0] = {a.x2, a.y1};
        dsc.p[1] = {a.x2, a.y2};
        dsc.p[2] = {a.x1, mid};
    }
    lv_draw_triangle(lv_event_get_layer(e), &dsc);
}

void NavBar::update_hints() {
    const auto page = view_model_.current_page();
    int index = -1;
    for (int i = 0; i < model::kMainPageCount; ++i) {
        if (model::kMainPages[i] == page) index = i;
    }
    if (index < 0) {
        lv_obj_add_flag(page_nav_, LV_OBJ_FLAG_HIDDEN);
    }
    else {
        lv_obj_remove_flag(page_nav_, LV_OBJ_FLAG_HIDDEN);
        lv_label_set_text_fmt(page_number_, "(%d)", index + 1);
    }

    const auto hints = hints_for(view_model_.current_page());
    const auto colors = view::palette(view_model_.is_dark_mode());
    for (std::size_t i = 0; i < kMaxHints; ++i) {
        if (!hints[i].action) {
            lv_obj_add_flag(items_[i], LV_OBJ_FLAG_HIDDEN);
            continue;
        }
        lv_obj_remove_flag(items_[i], LV_OBJ_FLAG_HIDDEN);
        lv_label_set_text(key_labels_[i], hints[i].key);
        lv_label_set_text(action_labels_[i], hints[i].action);
        lv_obj_set_style_text_color(key_labels_[i], colors.primary, 0);
        lv_obj_set_style_text_color(action_labels_[i], colors.text, 0);
    }
}

void NavBar::update_cb(lv_observer_t* observer, lv_subject_t*) {
    auto* nav_bar = static_cast<NavBar*>(lv_observer_get_user_data(observer));
    if (nav_bar) {
        nav_bar->update_hints();
    }
}

} // namespace view::widgets
