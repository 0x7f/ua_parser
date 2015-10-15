#include <fstream>
#include <sstream>

#include <gtest/gtest.h>

#include <json/reader.h>
#include <json/value.h>

#include "ua_parser.hpp"

static Json::Value load_json_from_file(const std::string& path)
{
    std::ifstream in{path.data()};
    if (!in.is_open())
    {
        throw std::runtime_error("Cannot open file: " + path);
    }

    std::stringstream buffer;
    buffer << in.rdbuf();

    Json::Value json;
    Json::Reader reader;
    if (!reader.parse(buffer.str(), json))
    {
        throw std::runtime_error("Error parsing json: " +
                                 reader.getFormattedErrorMessages());
    }

    return json;
}

TEST(UaParser, shouldParseFixtures)
{
    const auto parser = uap::UaParser{};
    const auto fixtures = load_json_from_file("test/fixtures.json");
    for (const auto& fixture : fixtures)
    {
        const auto result = parser.parse(fixture["userAgent"].asString());
        const auto& expectedResult = fixture["result"];
        EXPECT_EQ(expectedResult["osName"].asString(), result.osName);
        EXPECT_EQ(expectedResult["osVersion"].asString(), result.osVersion);
        EXPECT_EQ(expectedResult["browserName"].asString(), result.browserName);
        EXPECT_EQ(expectedResult["browserUnit"].asString(), result.browserUnit);
        EXPECT_EQ(expectedResult["deviceType"].asString(), result.deviceType);
        EXPECT_EQ(expectedResult["deviceModel"].asString(), result.deviceModel);
        EXPECT_EQ(expectedResult["deviceVendor"].asString(), result.deviceVendor);
    }
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
