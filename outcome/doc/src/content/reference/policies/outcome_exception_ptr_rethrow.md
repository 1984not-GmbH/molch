+++
title = "exception_ptr rethrow (Outcome)"
weight = 40
+++
# Header file `outcome_exception_ptr_rethrow.hpp`

<span id="standardese-outcome_exception_ptr_rethrow-hpp"></span>

<pre><code class="standardese-language-cpp"><span class="pre">#include</span>&nbsp;<span class="pre">&quot;</span><a href="../result_exception_ptr_rethrow#standardese-result_exception_ptr_rethrow-hpp"><span class="typ dec var fun">result_exception_ptr_rethrow.hpp</span></a><span class="pre">&quot;</span>

<span class="kwd">namespace</span>&nbsp;<span class="typ dec var fun">outcome_v2_xxx</span>
<span class="pun">{</span>
&nbsp;&nbsp;&nbsp;&nbsp;<span class="kwd">namespace</span>&nbsp;<span class="typ dec var fun">policy</span>
&nbsp;&nbsp;&nbsp;&nbsp;<span class="pun">{</span>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="kwd">template</span>&nbsp;<span class="pun">&lt;</span><span class="kwd">class</span>&nbsp;<span class="typ dec var fun">T</span><span class="pun">,</span>&nbsp;<span class="kwd">class</span>&nbsp;<span class="typ dec var fun">EC</span><span class="pun">,</span>&nbsp;<span class="kwd">class</span>&nbsp;<span class="typ dec var fun">E</span><span class="pun">&gt;</span>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="kwd">struct</span> <a href="#standardese-outcome_v2_xxx__policy__exception_ptr_rethrow-T-EC-E-"><span class="typ dec var fun">exception_ptr_rethrow</span></a><span class="pun">;</span>
&nbsp;&nbsp;&nbsp;&nbsp;<span class="pun">}</span>
<span class="pun">}</span>
</code></pre>

<span id="standardese-outcome_v2_xxx"></span>

<span id="standardese-outcome_v2_xxx__policy"></span>

### Struct `outcome_v2_xxx::policy::exception_ptr_rethrow`

<span id="standardese-outcome_v2_xxx__policy__exception_ptr_rethrow-T-EC-E-"></span>

<pre><code class="standardese-language-cpp"><span class="kwd">template</span>&nbsp;<span class="pun">&lt;</span><span class="kwd">class</span>&nbsp;<span class="typ dec var fun">T</span><span class="pun">,</span>&nbsp;<span class="kwd">class</span>&nbsp;<span class="typ dec var fun">EC</span><span class="pun">,</span>&nbsp;<span class="kwd">class</span>&nbsp;<span class="typ dec var fun">E</span><span class="pun">&gt;</span>
<span class="kwd">struct</span>&nbsp;<span class="typ dec var fun">exception_ptr_rethrow</span>
<span class="pun">{</span>
&nbsp;&nbsp;&nbsp;&nbsp;<span class="kwd">template</span>&nbsp;<span class="pun">&lt;</span><span class="kwd">class</span>&nbsp;<span class="typ dec var fun">Impl</span><span class="pun">&gt;</span>
&nbsp;&nbsp;&nbsp;&nbsp;<span class="kwd">static</span>&nbsp;<span class="kwd">constexpr</span>&nbsp;<span class="kwd">void</span> <a href="#standardese-outcome_v2_xxx__policy__exception_ptr_rethrow-T-EC-E-__wide_value_check-Impl--Impl---"><span class="typ dec var fun">wide_value_check</span></a><span class="pun">(</span><span class="typ dec var fun">Impl</span><span class="pun">&amp;&amp;</span>&nbsp;<span class="typ dec var fun">self</span><span class="pun">)</span><span class="pun">;</span>

&nbsp;&nbsp;&nbsp;&nbsp;<span class="kwd">template</span>&nbsp;<span class="pun">&lt;</span><span class="kwd">class</span>&nbsp;<span class="typ dec var fun">Impl</span><span class="pun">&gt;</span>
&nbsp;&nbsp;&nbsp;&nbsp;<span class="kwd">static</span>&nbsp;<span class="kwd">constexpr</span>&nbsp;<span class="kwd">void</span> <a href="#standardese-outcome_v2_xxx__policy__exception_ptr_rethrow-T-EC-E-__wide_error_check-Impl--Impl---"><span class="typ dec var fun">wide_error_check</span></a><span class="pun">(</span><span class="typ dec var fun">Impl</span><span class="pun">&amp;&amp;</span>&nbsp;<span class="typ dec var fun">self</span><span class="pun">)</span><span class="pun">;</span>

&nbsp;&nbsp;&nbsp;&nbsp;<span class="kwd">template</span>&nbsp;<span class="pun">&lt;</span><span class="kwd">class</span>&nbsp;<span class="typ dec var fun">Impl</span><span class="pun">&gt;</span>
&nbsp;&nbsp;&nbsp;&nbsp;<span class="kwd">static</span>&nbsp;<span class="kwd">constexpr</span>&nbsp;<span class="kwd">void</span> <a href="#standardese-outcome_v2_xxx__policy__exception_ptr_rethrow-T-EC-E-__wide_exception_check-Impl--Impl---"><span class="typ dec var fun">wide_exception_check</span></a><span class="pun">(</span><span class="typ dec var fun">Impl</span><span class="pun">&amp;&amp;</span>&nbsp;<span class="typ dec var fun">self</span><span class="pun">)</span><span class="pun">;</span>

&nbsp;&nbsp;&nbsp;&nbsp;<span class="kwd">template</span>&nbsp;<span class="pun">&lt;</span><span class="kwd">class</span>&nbsp;<span class="typ dec var fun">Impl</span><span class="pun">&gt;</span>
&nbsp;&nbsp;&nbsp;&nbsp;<span class="kwd">static</span>&nbsp;<span class="kwd">constexpr</span>&nbsp;<span class="kwd">void</span> <a href="../result_exception_ptr_rethrow#standardese-outcome_v2_xxx__policy__detail__base__narrow_value_check-Impl--Impl---"><span class="typ dec var fun">narrow_value_check</span></a><span class="pun">(</span><span class="typ dec var fun">Impl</span><span class="pun">&amp;&amp;</span>&nbsp;<span class="typ dec var fun">self</span><span class="pun">)</span>&nbsp;<span class="kwd">noexcept</span><span class="pun">;</span>

&nbsp;&nbsp;&nbsp;&nbsp;<span class="kwd">template</span>&nbsp;<span class="pun">&lt;</span><span class="kwd">class</span>&nbsp;<span class="typ dec var fun">Impl</span><span class="pun">&gt;</span>
&nbsp;&nbsp;&nbsp;&nbsp;<span class="kwd">static</span>&nbsp;<span class="kwd">constexpr</span>&nbsp;<span class="kwd">void</span> <a href="../result_exception_ptr_rethrow#standardese-outcome_v2_xxx__policy__detail__base__narrow_error_check-Impl--Impl---"><span class="typ dec var fun">narrow_error_check</span></a><span class="pun">(</span><span class="typ dec var fun">Impl</span><span class="pun">&amp;&amp;</span>&nbsp;<span class="typ dec var fun">self</span><span class="pun">)</span>&nbsp;<span class="kwd">noexcept</span><span class="pun">;</span>

&nbsp;&nbsp;&nbsp;&nbsp;<span class="kwd">template</span>&nbsp;<span class="pun">&lt;</span><span class="kwd">class</span>&nbsp;<span class="typ dec var fun">Impl</span><span class="pun">&gt;</span>
&nbsp;&nbsp;&nbsp;&nbsp;<span class="kwd">static</span>&nbsp;<span class="kwd">constexpr</span>&nbsp;<span class="kwd">void</span> <a href="../result_exception_ptr_rethrow#standardese-outcome_v2_xxx__policy__detail__base__narrow_exception_check-Impl--Impl---"><span class="typ dec var fun">narrow_exception_check</span></a><span class="pun">(</span><span class="typ dec var fun">Impl</span><span class="pun">&amp;&amp;</span>&nbsp;<span class="typ dec var fun">self</span><span class="pun">)</span>&nbsp;<span class="kwd">noexcept</span><span class="pun">;</span>
<span class="pun">};</span>
</code></pre>

Policy interpreting `EC` or `E` as a type for which `trait::has_exception_ptr_v<EC|E>` is true.

Any wide attempt to access the successful state where there is none causes: `std::rethrow_exception(policy::exception_ptr(.error()|.exception()))` appropriately.

### Function `outcome_v2_xxx::policy::throw_bad_result_access::narrow_value_check`

<span id="standardese-outcome_v2_xxx__policy__detail__base__narrow_value_check-Impl--Impl---"></span>

<pre><code class="standardese-language-cpp"><span class="kwd">template</span>&nbsp;<span class="pun">&lt;</span><span class="kwd">class</span>&nbsp;<span class="typ dec var fun">Impl</span><span class="pun">&gt;</span>
<span class="kwd">static</span>&nbsp;<span class="kwd">constexpr</span>&nbsp;<span class="kwd">void</span>&nbsp;<span class="typ dec var fun">narrow_value_check</span><span class="pun">(</span><span class="typ dec var fun">Impl</span><span class="pun">&amp;&amp;</span>&nbsp;<span class="typ dec var fun">self</span><span class="pun">)</span>&nbsp;<span class="kwd">noexcept</span><span class="pun">;</span>
</code></pre>

Performs a narrow check of state, used in the assume\_value() functions.

*Effects:* None.

-----

### Function `outcome_v2_xxx::policy::throw_bad_result_access::narrow_error_check`

<span id="standardese-outcome_v2_xxx__policy__detail__base__narrow_error_check-Impl--Impl---"></span>

<pre><code class="standardese-language-cpp"><span class="kwd">template</span>&nbsp;<span class="pun">&lt;</span><span class="kwd">class</span>&nbsp;<span class="typ dec var fun">Impl</span><span class="pun">&gt;</span>
<span class="kwd">static</span>&nbsp;<span class="kwd">constexpr</span>&nbsp;<span class="kwd">void</span>&nbsp;<span class="typ dec var fun">narrow_error_check</span><span class="pun">(</span><span class="typ dec var fun">Impl</span><span class="pun">&amp;&amp;</span>&nbsp;<span class="typ dec var fun">self</span><span class="pun">)</span>&nbsp;<span class="kwd">noexcept</span><span class="pun">;</span>
</code></pre>

Performs a narrow check of state, used in the assume\_error() functions

*Effects:* None.

-----

### Function `outcome_v2_xxx::policy::throw_bad_result_access::narrow_exception_check`

<span id="standardese-outcome_v2_xxx__policy__detail__base__narrow_exception_check-Impl--Impl---"></span>

<pre><code class="standardese-language-cpp"><span class="kwd">template</span>&nbsp;<span class="pun">&lt;</span><span class="kwd">class</span>&nbsp;<span class="typ dec var fun">Impl</span><span class="pun">&gt;</span>
<span class="kwd">static</span>&nbsp;<span class="kwd">constexpr</span>&nbsp;<span class="kwd">void</span>&nbsp;<span class="typ dec var fun">narrow_exception_check</span><span class="pun">(</span><span class="typ dec var fun">Impl</span><span class="pun">&amp;&amp;</span>&nbsp;<span class="typ dec var fun">self</span><span class="pun">)</span>&nbsp;<span class="kwd">noexcept</span><span class="pun">;</span>
</code></pre>

Performs a narrow check of state, used in the assume\_exception() functions

*Effects:* None.

-----

### Function `outcome_v2_xxx::policy::exception_ptr_rethrow::wide_value_check`

<span id="standardese-outcome_v2_xxx__policy__exception_ptr_rethrow-T-EC-E-__wide_value_check-Impl--Impl---"></span>

<pre><code class="standardese-language-cpp"><span class="kwd">template</span>&nbsp;<span class="pun">&lt;</span><span class="kwd">class</span>&nbsp;<span class="typ dec var fun">Impl</span><span class="pun">&gt;</span>
<span class="kwd">static</span>&nbsp;<span class="kwd">constexpr</span>&nbsp;<span class="kwd">void</span>&nbsp;<span class="typ dec var fun">wide_value_check</span><span class="pun">(</span><span class="typ dec var fun">Impl</span><span class="pun">&amp;&amp;</span>&nbsp;<span class="typ dec var fun">self</span><span class="pun">)</span><span class="pun">;</span>
</code></pre>

Performs a wide check of state, used in the value() functions

*Effects:* If outcome does not have a value, if it has an exception it rethrows that exception via `std::rethrow_exception()`, if it has an error it rethrows that error via `std::rethrow_exception()`, else it throws `bad_outcome_access`.

-----

### Function `outcome_v2_xxx::policy::exception_ptr_rethrow::wide_error_check`

<span id="standardese-outcome_v2_xxx__policy__exception_ptr_rethrow-T-EC-E-__wide_error_check-Impl--Impl---"></span>

<pre><code class="standardese-language-cpp"><span class="kwd">template</span>&nbsp;<span class="pun">&lt;</span><span class="kwd">class</span>&nbsp;<span class="typ dec var fun">Impl</span><span class="pun">&gt;</span>
<span class="kwd">static</span>&nbsp;<span class="kwd">constexpr</span>&nbsp;<span class="kwd">void</span>&nbsp;<span class="typ dec var fun">wide_error_check</span><span class="pun">(</span><span class="typ dec var fun">Impl</span><span class="pun">&amp;&amp;</span>&nbsp;<span class="typ dec var fun">self</span><span class="pun">)</span><span class="pun">;</span>
</code></pre>

Performs a wide check of state, used in the error() functions

*Effects:* If outcome does not have an error, it throws `bad_outcome_access`.

-----

### Function `outcome_v2_xxx::policy::exception_ptr_rethrow::wide_exception_check`

<span id="standardese-outcome_v2_xxx__policy__exception_ptr_rethrow-T-EC-E-__wide_exception_check-Impl--Impl---"></span>

<pre><code class="standardese-language-cpp"><span class="kwd">template</span>&nbsp;<span class="pun">&lt;</span><span class="kwd">class</span>&nbsp;<span class="typ dec var fun">Impl</span><span class="pun">&gt;</span>
<span class="kwd">static</span>&nbsp;<span class="kwd">constexpr</span>&nbsp;<span class="kwd">void</span>&nbsp;<span class="typ dec var fun">wide_exception_check</span><span class="pun">(</span><span class="typ dec var fun">Impl</span><span class="pun">&amp;&amp;</span>&nbsp;<span class="typ dec var fun">self</span><span class="pun">)</span><span class="pun">;</span>
</code></pre>

Performs a wide check of state, used in the exception() functions

*Effects:* If result does not have an exception, it throws `bad_outcome_access`.

-----

-----
