export const SeverityColors = new Map<string, string>([
  ["CRITICAL", "#ff4d4f"], // Ant Design's danger color (red)
  ["HIGH", "#ff7a45"], // A strong orange
  ["MEDIUM", "#faad14"], // Ant Design's warning color (yellow/orange)
  ["LOW", "#52c41a"], // Ant Design's success color (green)
  ["INFORMATIONAL", "#1890ff"], // Ant Design's primary color (blue)
  ["NONE", "#d9d9d9"], // A neutral grey for no severity
  ["UNKNOWN", "#bfbfbf"], // A lighter grey for unknown cases
  ["DEFAULT", "#d9d9d9"], // Default fallback color
]);

// Provides user-friendly text for severity levels, often used in tags.
export const SeverityTags = new Map<string, string>([
  ["CRITICAL", "Critical"],
  ["HIGH", "High"],
  ["MEDIUM", "Medium"],
  ["LOW", "Low"],
  ["INFORMATIONAL", "Info"],
  ["NONE", "None"],
  ["UNKNOWN", "Unknown"],
]);

// You can also add a function to get a color safely if needed elsewhere
export const getSeverityColor = (severity?: string): string => {
  if (!severity) return SeverityColors.get("DEFAULT") ?? "#d9d9d9";
  const upperSeverity = severity.toUpperCase();
  return SeverityColors.get(upperSeverity) ?? SeverityColors.get("UNKNOWN") ?? "#bfbfbf";
};

export const getSeverityTagText = (severity?: string): string => {
  if (!severity) return SeverityTags.get("UNKNOWN") ?? "Unknown"; // Or an empty string or 'N/A'
  const upperSeverity = severity.toUpperCase();
  return SeverityTags.get(upperSeverity) ?? severity; // Fallback to the original severity string if no tag is defined
};
