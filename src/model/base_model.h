/*
 * SPDX-FileCopyrightText: 2026 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

namespace model {

enum class AppPage {
    Password = 0, // sudo password entry
    Status   = 1, // on/off, defaults, whitelist button, undo
    Rules    = 2, // rule list, delete, add
    Ports    = 3, // listening ports with verdicts
    Networks = 4, // current network and whitelist
    AddRule  = 5, // form + presets
    FreeForm = 6, // typed ufw rule
    Confirm  = 7, // command, dry-run, SSH warning
    Message  = 8, // errors and long results
};

// Pages reachable with Left/Right, in order.
constexpr AppPage kMainPages[] = {AppPage::Status, AppPage::Rules, AppPage::Ports,
                                  AppPage::Networks};
constexpr int kMainPageCount = 4;

inline bool is_main_page(AppPage page) {
    for (const auto p : kMainPages) {
        if (p == page) return true;
    }
    return false;
}

class BaseModel {
public:
    const char* app_title() const;

    bool dark_mode() const;
    void set_dark_mode(bool enabled);
    void toggle_dark_mode();

    AppPage current_page() const;
    void set_current_page(AppPage page);

private:
    bool dark_mode_ = false;
    AppPage current_page_ = AppPage::Status;
};

} // namespace model
