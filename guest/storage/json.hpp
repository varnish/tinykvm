#pragma once
#include <rapidjson/allocators.h>
#include <rapidjson/document.h>
#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

typedef rapidjson::GenericDocument<rapidjson::UTF8<>, rapidjson::MemoryPoolAllocator<>, rapidjson::MemoryPoolAllocator<>> JsonDocument;
