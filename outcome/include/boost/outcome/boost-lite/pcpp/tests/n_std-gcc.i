# 1 "test/test-c/n_std.c"
# 1 "<built-in>"
# 1 "<command-line>"
# 1 "/usr/include/stdc-predef.h" 1 3 4
# 1 "<command-line>" 2
# 1 "test/test-c/n_std.c"
# 18 "test/test-c/n_std.c"
# 1 "test/test-c/defs.h" 1
# 19 "test/test-c/n_std.c" 2
# 30 "test/test-c/n_std.c"
void n_1( void);
void n_2( void);
void n_3( void);
void n_4( void);
void n_5( void);
void n_6( void);
void n_7( void);
void n_9( void);
void n_10( void);
void n_11( void);
void n_12( void);
void n_13( void);
void n_13_5( void);
void n_13_7( void);
void n_13_8( void);
void n_13_13( void);
void n_15( void);
void n_18( void);
void n_19( void);
void n_20( void);
void n_21( void);
void n_22( void);
void n_23( void);
void n_24( void);
void n_25( void);
void n_26( void);
void n_27( void);
void n_28( void);
void n_29( void);
void n_30( void);
void n_32( void);
void n_37( void);

int main( void)
{

    n_2();
    n_3();

    n_5();
    n_6();
    n_7();
    n_9();
    n_10();
    n_11();
    n_12();
    n_13();
    n_13_5();
    n_13_7();
    n_13_8();
    n_13_13();
    n_15();
    n_18();
    n_19();
    n_20();
    n_21();
    n_22();
    n_23();
    n_24();
    n_25();
    n_26();
    n_27();
    n_28();
    n_29();
    n_30();
    n_32();
    n_37();
    puts( "<End of \"n_std.c\">");
    return 0;
}

char quasi_trigraph[] = { '?', '?', ' ', '?', '?', '?', ' '
            , '?', '?', '%', ' ', '?', '?', '^', ' ', '?', '#', '\0' };

void n_2( void)

{
    int ab = 1, cd = 2, ef = 3, abcde = 5;





    assert( ab + cd + ef == 6);
# 122 "test/test-c/n_std.c"
    assert (ab + cd + ef == 6);


    assert (strcmp( "abcde",
     "abcde") == 0);


    assert( abcde
   == 5);

}

void n_3( void)

{
    int abcd = 4;


    assert( strcmp( "abc de", "abc de") == 0);
# 156 "test/test-c/n_std.c"
    assert( abcd == 4);
}

void n_5( void)



{
    int abcde = 5;


    assert( abcde == 5);
}
# 178 "test/test-c/n_std.c"
void n_6( void)

{
    int abc = 3;

    assert( isalpha( 'a'));



# 1 "test/test-c/header.h" 1
# 188 "test/test-c/n_std.c" 2
    assert( abc == 3);



# 1 "test/test-c/header.h" 1
# 193 "test/test-c/n_std.c" 2
    assert( abc == 3);
}

void n_7( void)

{
# 1234 "cpp"
    assert( 1234 == 1234);
    assert( strcmp( "cpp", "cpp") == 0);
# 2345 "cpp"
    assert( 2345 == 2345);
    assert( strcmp( "cpp", "cpp") == 0);
# 1234 "n_7.c"
    assert( 1234 == 1234);
    assert( strcmp( "n_7.c", "n_7.c") == 0);
}
# 218 "n_std.c"

void n_9( void)

{


       
#pragma who knows ?
}

void n_10( void)

{







    assert( 1);
# 251 "n_std.c"
}

void n_11( void)

{
    int abc = 1, a = 0;







    assert( abc);


    assert( abc);
# 279 "n_std.c"
}





void n_12( void)

{


    fputs( "Bad evaluation of long.\n", stderr);


    fputs( "Bad evaluation of long.\n", stderr);
# 325 "n_std.c"
}

void n_13( void)
# 343 "n_std.c"
{
# 363 "n_std.c"
}

void n_13_5( void)

{
# 387 "n_std.c"
}

void n_13_7( void)

{
# 406 "n_std.c"
}

void n_13_8( void)

{
# 439 "n_std.c"
}

void n_13_13( void)

{
# 466 "n_std.c"
}

void n_15( void)

{



    assert( 1);
# 483 "n_std.c"
    assert( 1);

}

void n_18( void)




{
    int c = 3;


    assert( (1-1) == 0);





    assert( ( c ) == 3);



    assert( strcmp( "n1:n2", "n1:n2") == 0);
}

void n_19( void)

{
    int c = 1;
# 521 "n_std.c"
    assert( ( c ) == 1);
}

void n_20( void)

{


    double fl;
    assert( sizeof fl == sizeof (double));
}

void n_21( void)

{
    int a = 1, x = 2, y = -3;



    assert( - - -a == -1);






    assert( x- -y == -1);
}

void n_22( void)

{



    assert( strcmp( "12E+EXP", "12E+EXP") == 0);


    assert( strcmp( ".2e-EXP", ".2e-EXP") == 0);



    assert( strcmp( "12+1", "12+1") == 0);
}

void n_23( void)

{
    int xy = 1;


    assert( xy == 1);




    assert( .12e+2 == 12.0);
}

void n_24( void)

{

    assert( strcmp( "a+b", "a+b") == 0);



    assert( strcmp( "ab + cd"
             , "ab + cd") == 0);



    assert( strcmp( "'\"' + \"' \\\"\"", "'\"' + \"' \\\"\"") == 0);



    assert( strcmp( "\"abc\""
   , "\"abc\"") == 0);




    assert( strcmp( "x-y", "x-y") == 0);
}

void n_25( void)



{
    int a = 1, b = 2, abc = 3, MACRO_0MACRO_1 = 2;






    assert( (a,b - 1) == 1);


    assert( ( - a) == -1);


    assert( abc == 3);


    assert( MACRO_0MACRO_1 == 2);


    assert( strcmp( "ZERO_TOKEN", "ZERO_TOKEN") == 0);
}
# 648 "n_std.c"
int f( int a)
{
    return a;
}

int g( int a)
{
    return a * 2;
}


void n_26( void)

{
    int x = 1;
    int AB = 1;
    int Z[1];
    Z[0] = 1;




    assert( Z[0] == 1);





    assert( AB == 1);




    assert( x + f(x) == 2);





    assert( x + x + g( x) == 4);



    assert( Z[0] + f(Z[0]) == 2);
}

void n_27( void)




{
    int a = 1, b = 2, c, m = 1, n = 2;
# 711 "n_std.c"
    assert( 1 + 2 + 3 + 4 + 5 + 6 + 7 + 8 == 36);






    assert( (1) + (1 + 2) + 1 + 2 + 1 + 2 + 3 + 1 + 2 + 3 + 4 == 23);


    assert( 1 == 1);






    assert( ((a) - (b)) == -1);


    c = (a - b);
    assert( c == -1);





    assert( n == 2);
}

void n_28( void)


{
    char * date = "Feb 11 2017";


    assert( strcmp( "n_std.c", "n_std.c") == 0);


    assert( 751 == 779);


    assert( strlen( "Feb 11 2017") == 11);
    assert( date[ 4] != '0');


    assert( strlen( "17:44:49") == 8);


    assert( 1);


    assert( __STDC_VERSION__ >= 199409L);


# 1 "test/test-c/line.h" 1


{
    char * file = "test/test-c/line.h";
    file += strlen( file) - 6;
    assert( 6 == 6 && strcmp( file, "line.h") == 0);
}
# 768 "n_std.c" 2
}

void n_29( void)

{
    int DEFINED = 1;




    assert( DEFINED == 1);



}

void n_30( void)






{



    int a = 1, b = 2, c = 3;


    assert
    (
        a + b + c





        == 6
    );
}

void n_32( void)

{
# 822 "n_std.c"
}

void n_37( void)

{






    int ABCDEFGHIJKLMNOPQRSTUVWXYZabcde = 31;
    int ABCDEFGHIJKLMNOPQRSTUVWXYZabcd_ = 30;
    int nest = 0;


    assert(
        ABCDEFGHIJKLMNOPQRSTUVWXYZabcde

        == 31);



    assert( ABCDEFGHIJKLMNOPQRSTUVWXYZabcd_ == 30);


    nest = 0;
# 865 "n_std.c"
                                nest = 8;
# 874 "n_std.c"
    assert( nest == 8);


    nest = 0;
# 1 "test/test-c/nest1.h" 1


    nest = 1;

# 1 "test/test-c/nest2.h" 1


    nest = 2;

# 1 "test/test-c/nest3.h" 1


    nest = 3;

# 1 "test/test-c/nest4.h" 1


    nest = 4;

# 1 "test/test-c/nest5.h" 1


    nest = 5;

# 1 "test/test-c/nest6.h" 1


    nest = 6;

# 1 "test/test-c/nest7.h" 1


    nest = 7;

# 1 "test/test-c/nest8.h" 1



    nest = 8;
# 5 "test/test-c/nest7.h" 2
# 5 "test/test-c/nest6.h" 2
# 5 "test/test-c/nest5.h" 2
# 5 "test/test-c/nest4.h" 2
# 5 "test/test-c/nest3.h" 2
# 5 "test/test-c/nest2.h" 2
# 5 "test/test-c/nest1.h" 2
# 879 "n_std.c" 2
    assert( nest == 8);






    nest = 32;

    assert( nest == 32);


    {
        char * extremely_long_string =
"123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567"







        ;
        assert( strlen( extremely_long_string) == 507);
    }


    {
    int a123456789012345678901234567890 = 123450;
    int b123456789012345678901234567890 = 123451;
    int c123456789012345678901234567890 = 123452;
    int d123456789012345678901234567890 = 123453;
    int e123456789012345678901234567890 = 123454;
    int f123456789012345678901234567890 = 123455;
    int A123456789012345678901234567890 = 123456;
    int B123456789012345678901234567890 = 123457;
    int C123456789012345678901234567890 = 123458;
    int D1234567890123456789012 = 123459;
        assert( a123456789012345678901234567890 == 123450
            && D1234567890123456789012 == 123459);
    }






# 1 "test/test-c/m1024.h" 1
# 927 "n_std.c" 2
    assert( 1);
}
