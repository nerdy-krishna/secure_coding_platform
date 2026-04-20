// secure-code-ui/src/shared/api/seedService.ts
import apiClient from "./apiClient";

export interface SeedResult {
  frameworks_added: number;
  agents_added: number;
  templates_added: number;
  mappings_refreshed: number;
  reset: boolean;
}

export const seedService = {
  /**
   * Re-seed the platform defaults.
   * - `reset=false` (default): only inserts missing rows. Admin customisations
   *   stay intact.
   * - `reset=true`: drops the managed default frameworks / agents / prompt
   *   templates first. Destructive; use to recover from a broken state.
   */
  seedDefaults: async (reset = false): Promise<SeedResult> => {
    const res = await apiClient.post<SeedResult>(
      `/admin/seed/defaults?reset=${reset}`,
    );
    return res.data;
  },
};
