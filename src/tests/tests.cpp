#include "gtest/gtest.h"
#include "../sniffer/includes.h"

TEST(get_dns_name_tests, first_arg_is_nullptr)
{   
    in_addr test_addr;
    EXPECT_EQ(EXIT_FAILURE, get_dns_name(nullptr, test_addr));
}
TEST(get_dns_name_tests, dns_name_does_is_exist)
{
    in_addr test_addr;
    memset(&test_addr, 0, sizeof(in_addr));
    char empty_name[100] = "none";
    EXPECT_EQ(EXIT_SUCCESS, get_dns_name(empty_name, test_addr));
    EXPECT_STREQ("0.0.0.0", empty_name);
}
TEST(set_log_settings_tests, arg_is_nullptr)
{
    EXPECT_EQ(EXIT_FAILURE, set_log_settings(nullptr));
}
TEST(set_log_settings_tests, arg_is_not_nullptr)
{
    EXPECT_EQ(EXIT_SUCCESS, set_log_settings("prog"));
}
TEST(arguments_check_tests, first_arg_is_zero)
{
    char test1[256] = "test_string";
    size_t test2 = 0, test3 = 0;
    char* argv[] = {"first", "-f", "filter_exp"};
    EXPECT_EQ(EXIT_SUCCESS, arguments_check(0, argv, test2, test1, test3));
    EXPECT_STREQ("test_string", test1);
}
TEST(arguments_check_tests, second_arg_is_nullptr)
{
    char test1[256] = "test_string";
    size_t test2 = 0, test3 = 0;
    EXPECT_EQ(EXIT_FAILURE, arguments_check(3, nullptr, test2, test1, test3));
}
TEST(arguments_check_tests, fourth_arg_is_nullptr)
{
    size_t test2 = 0, test3 = 0;
    char* argv[] = {"first", "-f", "filter_exp"};
    EXPECT_EQ(EXIT_FAILURE, arguments_check(3, argv, test2, nullptr, test3));
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
