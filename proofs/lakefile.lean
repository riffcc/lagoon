import Lake
open Lake DSL

package «lagoon-mesh-proofs» where
  leanOptions := #[
    ⟨`autoImplicit, false⟩,
    ⟨`pp.unicode.fun, true⟩
  ]

require mathlib from git
  "https://github.com/leanprover-community/mathlib4"

@[default_target]
lean_lib LagoonMesh where
  roots := #[`LagoonMesh]
  globs := #[Glob.submodules `LagoonMesh]
