import path from "node:path";
import { fileURLToPath } from "node:url";

export type RuntimePathsInput = {
  appPath: string;
  compiledMainUrl: string;
  isPackaged: boolean;
};

export type RuntimePaths = {
  rendererAssetRoot: string;
  preloadPath: string;
};

export function resolveRuntimePaths(input: RuntimePathsInput): RuntimePaths {
  if (input.isPackaged) {
    return {
      rendererAssetRoot: path.join(input.appPath, "dist", "renderer"),
      preloadPath: path.join(input.appPath, "dist", "main", "preload", "index.js")
    };
  }

  const compiledMainDir = path.dirname(fileURLToPath(input.compiledMainUrl));

  return {
    rendererAssetRoot: path.resolve(compiledMainDir, "../../renderer"),
    preloadPath: path.resolve(compiledMainDir, "../preload/index.js")
  };
}
