#!/usr/bin/python
# Benchmark Outcome against other stuff
# (C) 2017 Niall Douglas http://www.nedproductions.biz/
# Created: Mar 2017

from __future__ import print_function
import sys, os, subprocess, shlex, time

class ErrorHandlingSystem(object):
    "Base class for an error handling system"

    def __init__(self):
        pass

    def preamble(self, idx):
        "Preamble written out before each source file"
        return ''

    def function_cont(self, name):
        "Function signature"
        return 'extern int %s(int par)' % name

    def function_final(self):
        "Function implementation for final function zero"
        return r'''{ return par ? -1 : 0; }'''

    def generate_sources(self, no):
        "Generate no source files calling into one another"
        for n in xrange(0, no):
            with open("source%04d.cpp" % n, 'wt') as oh:
                oh.write(self.preamble(n))
                oh.write(r'''extern volatile int counter;
struct RAII { RAII() { ++counter; } ~RAII() { --counter; } };
''')
                if n:
                    oh.write(self.function_cont("funct%04d" % (n-1)) + ';\n')
                oh.write(self.function_cont("funct%04d" % n))
                if n:
                    oh.write(r'''
{
  RAII raii;
  return ''' + ("funct%04d" % (n-1)) + r'''(par + 1);
}
''')
                else:
                    oh.write(self.function_final())
        with open("function.h", 'wt') as oh:
            oh.write(self.function_cont("funct%04d" % (no-1)) + ';\n')
            oh.write("#define FUNCTION funct%04d\n" % (no-1))
            oh.write("#define NESTING %d\n" % (no))

class ExceptionThrow(ErrorHandlingSystem):
    def preamble(self, idx):
        return '#include <exception>\n' if idx == 0 else ''
    def function_final(self):
        return r'''{ throw std::exception(); }'''

class ResultErrorValue(ErrorHandlingSystem):
    def preamble(self, idx):
        return '#include "../include/outcome/result.hpp"\n'
    def function_cont(self, name):
        return 'extern OUTCOME_V2_NAMESPACE::result<int> %s(int par)' % name
    def function_final(self):
        return r'''{ return par; }'''

class ResultErrorError(ResultErrorValue):
    def function_final(self):
        return r'''{ return std::error_code(5, std::generic_category()); }'''

class ResultExceptionValue(ResultErrorValue):
    def function_cont(self, name):
        return 'extern OUTCOME_V2_NAMESPACE::result<int, std::exception_ptr> %s(int par)' % name
    def function_final(self):
        return r'''{ return par; }'''
        
class ResultExceptionError(ResultExceptionValue):
    def function_cont(self, name):
        return 'extern OUTCOME_V2_NAMESPACE::result<int, std::exception_ptr> %s(int par)' % name
    def function_final(self):
        return r'''{ return std::make_exception_ptr(std::exception()); }'''
        
matrix = [
    ('integer-returns', ErrorHandlingSystem),
    ('exception-throw', ExceptionThrow),
    ('result-error-value', ResultErrorValue),
    ('result-error-error', ResultErrorError),
    ('result-excpt-value', ResultExceptionValue),
    ('result-excpt-error', ResultExceptionError),
]

if sys.platform == 'win32':
    compilers = [
        ('msvc1912-noexcept', r'cl /nologo /std:c++latest /O2 /Gy /MD /Fe%s /I..\\..'),
        ('msvc1912', r'cl /nologo /std:c++latest /O2 /Gy /MD /EHsc /Fe%s /I..\\..'),
        ('msvc1912-ltcg', r'cl /nologo /std:c++latest /O2 /Gy /GL /MD /EHsc /Fe%s /I..\\..'),
    ]
elif sys.platform == 'darwin':
    compilers = [
        ('xcode82', r'clang++ -std=c++14 -O3 -g -o %s'),
    ]
else:
    compilers = [
        ('gcc72-noexcept', r'g++-7 -std=c++17 -fno-exceptions -O3 -g -o %s -I../..'),
        ('gcc72', r'g++-7 -std=c++17 -O3 -g -o %s -I../..'),
        ('gcc72-lto', r'g++-7 -std=c++17 -O3 -g -flto -o %s -I../..'),
        ('clang50', r'clang++-5.0 -std=c++17 -O3 -g -o %s -I../..'),
#        ('clang40-lto', r'clang++-4.0 -std=c++14 -O3 -g -flto -o %s'),  not working yet
    ]

SOURCES=10
if len(sys.argv)>1:
    SOURCES = int(sys.argv[1])

with open('results-'+sys.platform+'.csv', 'wt') as resultsh:
    resultsh.write('"Compiler"')
    for m in matrix:
        resultsh.write(',"'+m[0]+'"')
    resultsh.write('\n')
    for compiler in compilers:
        resultsh.write('"'+compiler[0]+'"')
        for m in matrix:
            if 'noexcept' in compiler[0] and m[0] == 'exception-throw':
                resultsh.write(',')
                continue
            instance = m[1]()
            try:
                exename = m[0]+'_'+compiler[0]
                print("\nGenerating sources for", exename, "...")
                instance.generate_sources(SOURCES)
                args = shlex.split(compiler[1] % exename)
                args.append("runner.cpp")
                for n in xrange(0, SOURCES):
                    args.append("source%04d.cpp" % n)
                if sys.platform == 'win32':
                    args.append("/link")
                    args.append("/OPT:REF,ICF")
                #print(' '.join(args))
                try:
                    print("Compiling", exename, "...")
                    compile_begin = time.clock()
                    print(subprocess.check_output(args))
                    compile_end = time.clock()
                    print("Compile took", compile_end-compile_begin, "secs. Running executable ...")
                except subprocess.CalledProcessError as e:
                    print(e.output)
                    raise
            finally:
                for n in xrange(0, SOURCES):
                    if os.path.exists("source%04d.cpp" % n):
                        os.remove("source%04d.cpp" % n)
                    if os.path.exists("source%04d.obj" % n):
                        os.remove("source%04d.obj" % n)
                os.remove("function.h")
                #if os.path.exists(exename):
                #    os.remove(exename)
                #if os.path.exists(exename+'.exe'):
                #    os.remove(exename+'.exe')
                if os.path.exists("runner.obj"):
                    os.remove("runner.obj")
            if sys.platform != 'win32':
                exename = './' + exename
            result = subprocess.check_output([exename])
            resultsh.write(',' + result.rstrip())
            resultsh.flush()
        resultsh.write('\n')
