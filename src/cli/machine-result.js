/** The `--machine` audit as one scan result. Loaded on demand, because most scans don't read the machine. */
export async function machineScanResult({ onPhase }) {
  const { auditMachine } = await import("../../lib/machine.js");
  const machine = await auditMachine({ onPhase });
  return { target: "this machine", mode: "machine", timestamp: new Date().toISOString(), duration: 0, machine, findings: machine.findings };
}
