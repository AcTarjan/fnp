file(REMOVE_RECURSE
  "libfnp-api.pdb"
  "libfnp-api.so"
)

# Per-language clean rules from dependency scanning.
foreach(lang C)
  include(CMakeFiles/fnp-api.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
