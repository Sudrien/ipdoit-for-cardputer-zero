/*
 * SPDX-License-Identifier: MIT
 */

// Small gettext-style translation layer: tr("English text") returns the text in the
// user's language, or the English text itself when there is no translation.
//
// The language comes from the environment the launcher passes to the app, the way
// gettext picks it: IPDOIT_LANG, then LANGUAGE (ignored when the locale is C), LC_ALL,
// LC_MESSAGES, LANG. zh* -> Simplified Chinese, ja* -> Japanese, anything else English.
// setlocale() is never called, so no system locale needs to be installed.
//
// Terminology follows ufw's own zh_CN / ja catalogs: ufw keywords (allow, deny, reject,
// limit, in, out, any, tcp, udp) and command syntax stay English, as ufw leaves them.

#pragma once

#include <cstddef>
#include <functional>
#include <string>

namespace i18n {

enum class Lang { En, ZhCN, Ja };

// Language for an environment, given a getenv-like lookup (testable).
Lang detect(const std::function<const char*(const char*)>& getenv_fn);

// The process language (detected from the environment on first use).
Lang current();
void set_language(Lang lang); // overrides detection; for tests and the simulator

const char* lang_code(Lang lang); // "en", "zh-CN", "ja"

// True when the language needs a CJK font.
bool needs_cjk();

// Translation of an English message. The returned pointer is static (the table entry, or
// `english` itself when untranslated), so it is safe to keep.
const char* tr(const char* english);
std::string tr(const std::string& english);

// printf() with the translated format string. The English format is what the compiler
// checks against the arguments; translations keep the same conversions in the same order
// (checked by i18n_tests).
std::string format(const char* english_format, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 1, 2)))
#endif
    ;

// Longest prefix of `text` that is at most `max_bytes` long and does not end inside a
// UTF-8 sequence.
std::size_t utf8_fit(const char* text, std::size_t max_bytes);

// The translation table, for tests.
struct Entry {
    const char* en;
    const char* zh_cn;
    const char* ja;
};
const Entry* entries(std::size_t& count);

} // namespace i18n
