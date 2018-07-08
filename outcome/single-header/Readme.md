Herein lie multiple single header editions of Outcome:

<dl>
  <dt>`basic.hpp`</dt>
  <dd>An inclusion of `basic_outcome.hpp` + `try.hpp` which includes as few system
  headers as possible in order to give an absolute minimum compile time
  impact edition of Outcome. See https://github.com/ned14/stl-header-heft.
  </dd>
  <dt>`outcome.hpp`</dt>
  <dd>An inclusion of `outcome.hpp` which brings in all the specialisations
  for the `std` STL types, plus iostreams support. If you don't know which
  edition to use, you should use this one, it ought to "just work".</dd>
</dl>
