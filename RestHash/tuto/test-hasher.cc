#define BOOST_TEST_MODULE your_test_module
#include <boost/test/included/unit_test.hpp>
#include "./include/hascompare.h"
#include "./Hasher.cc"

BOOST_AUTO_TEST_CASE( test_init ) {
    std::vector<int> a{1, 2};
    std::vector<int> b{1, 2};
    BOOST_TEST( a == b );
}

BOOST_AUTO_TEST_CASE( test_bis )
{
 
}
