// Reports where the helper packages are declared; nothing is installed here.
export function bootstrap(root) {
  return { root, packages: "declared in package.json" };
}
