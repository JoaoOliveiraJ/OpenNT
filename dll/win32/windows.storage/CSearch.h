/*
 * PROJECT:     OpenNT Windows Storage
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Structured query conditions and the search results folder
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif.ing@outlook.com>
 */

#pragma once

#include <structuredquery.h>

BOOL SQ_EvaluateCondition(ICondition *pCondition, LPCWSTR pszPath, const WIN32_FIND_DATAW *pFindData);
