/**
 * Scan profile presets.
 */

export const PROFILES = {
  quick: {
    label: "Quick",
    description: "Headers, OpenAPI, auth smoke tests — skips Retire.js and param discovery",
    recon: false,
    deep: false,
    fuzz: false,
    skipRetireJs: true,
    skipParamDiscovery: true,
  },
  standard: {
    label: "Standard",
    description: "Full non-destructive scan (default)",
    recon: false,
    deep: false,
    fuzz: false,
    skipRetireJs: false,
    skipParamDiscovery: false,
  },
  deep: {
    label: "Deep",
    description: "Maximum coverage: recon + injection probes + API fuzzing",
    recon: true,
    deep: true,
    fuzz: true,
    skipRetireJs: false,
    skipParamDiscovery: false,
  },
};

export function resolveScanOptions(opts) {
  const profileName = opts.profile || "standard";
  const profile = PROFILES[profileName];

  if (!profile) {
    throw new Error(`Unknown profile "${profileName}". Use: quick, standard, or deep.`);
  }

  const all = opts.all === true;

  return {
    profile: profileName,
    recon: all || opts.recon === true || profile.recon,
    deep: all || opts.deep === true || profile.deep,
    fuzz: all || opts.fuzz === true || profile.fuzz,
    skipRetireJs: profile.skipRetireJs,
    skipParamDiscovery: profile.skipParamDiscovery,
  };
}
