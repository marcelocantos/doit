package builtin

import "github.com/marcelocantos/doit/internal/cap"

// RegisterAll adds all built-in capabilities to the registry.
func RegisterAll(r *cap.Registry) {
	r.Register(&Cat{})
	r.Register(&Chmod{})
	r.Register(&Cp{})
	r.Register(&Find{})
	r.Register(&Git{})
	r.Register(&GoCmd{})
	r.Register(&Grep{})
	r.Register(&Head{})
	r.Register(&Ls{})
	r.Register(&Make{})
	r.Register(&Mkdir{})
	r.Register(&Mv{})
	r.Register(&Rm{})
	r.Register(&Sort{})
	r.Register(&Tail{})
	r.Register(&Tee{})
	r.Register(&Tr{})
	r.Register(&Uniq{})
	r.Register(&Wc{})
}
