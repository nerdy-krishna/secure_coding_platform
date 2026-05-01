// secure-code-ui/src/shared/api/seedService.ts
import apiClient from "./apiClient";

export interface SeedResult {
  frameworks_added: number;
  agents_added: number;
  templates_added: number;
  mappings_refreshed: number;
  reset: boolean;
}

// V02.4.1: module-scoped in-flight guard prevents concurrent/rapid-fire calls.
let inFlight: Promise<SeedResult> | null = null;

export const seedService = {
  /**
   * Re-seed the platform defaults.
   * - `reset=false` (default): only inserts missing rows. Admin customisations
   *   stay intact.
   * - `reset=true`: drops the managed default frameworks / agents / prompt
   *   templates first. Destructive; use to recover from a broken state.
   *
   * TODO (V2.3.5): the destructive reset=true path should require a second-superuser
   * approval token passed as reset_approval_token so the backend can enforce two-superuser
   * sign-off before any factory wipe. Add the parameter and append &approval=<token>
   * once the backend endpoint supports it.
   */
  seedDefaults: async (reset = false): Promise<SeedResult> => {
    // V02.4.1: return the existing promise if a call is already in progress.
    if (inFlight) return inFlight;

    // V02.2.1: coerce to strict boolean so any non-boolean argument (e.g. from
    // an any-typed JS shim) cannot smuggle unexpected querystring fragments.
    const flag = reset === true;

    // V15.3.5: use axios params option for explicit, URLSearchParams-encoded
    // serialisation; coerce to known string shape to guard against type-juggling
    // if the signature changes.
    inFlight = apiClient
      .post<SeedResult>("/admin/seed/defaults", undefined, {
        params: { reset: flag ? "true" : "false" },
      })
      .then((r) => r.data)
      .finally(() => {
        inFlight = null;
      });

    return inFlight;
  },
};
