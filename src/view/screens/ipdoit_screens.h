/*
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include "base_screen.h"

#include <string>
#include <vector>

namespace screen {

// Base for Ipdoit pages: redraws from the view model whenever its revision bumps.
class IpdoitScreen : public BaseScreen {
public:
    IpdoitScreen(viewmodel::BaseViewModel& view_model, app::AssetManager& assets);

protected:
    void build_content(lv_obj_t* content) override;
    virtual void build(lv_obj_t* column) = 0; // create widgets once
    virtual void refresh() = 0;               // update them from the view model

    // Shared helpers
    lv_obj_t* make_label(lv_obj_t* parent, uint32_t size, bool bold = false, const char* text = "");
    void set_muted(lv_obj_t* label);
    void set_tone(lv_obj_t* label, int tone); // 0 normal, 1 good, 2 bad, 3 warn, 4 muted, 5 accent

    // A scrollable list of one-line rows with a highlighted selection (-1 for none).
    lv_obj_t* make_list(lv_obj_t* parent);
    // Rows may contain '\t'-separated columns placed at the x offsets in `columns`.
    void fill_list(lv_obj_t* list, const std::vector<std::string>& rows, int selected,
                   const std::vector<int>& tones = {}, const std::vector<int>& columns = {});
    // Shared Left/Right page switching on main pages. Returns true if handled.
    bool handle_main_keys(uint32_t key);

private:
    static void revision_cb(lv_observer_t* observer, lv_subject_t* subject);
};

class PasswordScreen : public BaseScreen {
public:
    PasswordScreen(viewmodel::BaseViewModel& view_model, app::AssetManager& assets);

private:
    void build_content(lv_obj_t* content) override;
    bool handle_key(uint32_t key) override;
};

#define IPDOIT_SCREEN(Name, ...)                                                  \
    class Name : public IpdoitScreen {                                            \
    public:                                                                       \
        Name(viewmodel::BaseViewModel& view_model, app::AssetManager& assets)     \
            : IpdoitScreen(view_model, assets) {                                  \
            init();                                                               \
        }                                                                         \
                                                                                  \
    private:                                                                      \
        void build(lv_obj_t* column) override;                                    \
        void refresh() override;                                                  \
        bool handle_key(uint32_t key) override;                                   \
        __VA_ARGS__                                                               \
    };

IPDOIT_SCREEN(StatusScreen,
              lv_obj_t* state_ = nullptr; lv_obj_t* defaults_ = nullptr;
              lv_obj_t* network_ = nullptr; lv_obj_t* counts_ = nullptr;
              lv_obj_t* info_ = nullptr;)
IPDOIT_SCREEN(RulesScreen, lv_obj_t* header_ = nullptr; lv_obj_t* list_ = nullptr;)
IPDOIT_SCREEN(PortsScreen, lv_obj_t* header_ = nullptr; lv_obj_t* list_ = nullptr;)
IPDOIT_SCREEN(NetworksScreen, lv_obj_t* header_ = nullptr; lv_obj_t* list_ = nullptr;)
IPDOIT_SCREEN(AddRuleScreen, lv_obj_t* list_ = nullptr; lv_obj_t* footer_ = nullptr;)
IPDOIT_SCREEN(FreeFormScreen, lv_obj_t* field_ = nullptr; lv_obj_t* text_ = nullptr;
              lv_obj_t* footer_ = nullptr;)
IPDOIT_SCREEN(ConfirmScreen, lv_obj_t* title_ = nullptr; lv_obj_t* scroller_ = nullptr;
              lv_obj_t* command_ = nullptr; lv_obj_t* note_ = nullptr;
              lv_obj_t* warning_ = nullptr; lv_obj_t* phase_ = nullptr;)
IPDOIT_SCREEN(MessageScreen, lv_obj_t* title_ = nullptr; lv_obj_t* scroller_ = nullptr;
              lv_obj_t* text_ = nullptr;)

#undef IPDOIT_SCREEN

} // namespace screen
