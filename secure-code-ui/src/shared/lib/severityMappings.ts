export const SeverityColors: { [key: string]: string } = {
  CRITICAL: "#ff4d4f", // Ant Design's danger color (red)
  HIGH: "#ff7a45", // A strong orange
  MEDIUM: "#faad14", // Ant Design's warning color (yellow/orange)
  LOW: "#52c41a", // Ant Design's success color (green)
  INFORMATIONAL: "#1890ff", // Ant Design's primary color (blue)
  NONE: "#d9d9d9", // A neutral grey for no severity
  UNKNOWN: "#bfbfbf", // A lighter grey for unknown cases
  DEFAULT: "#d9d9d9", // Default fallback color
};

// Provides user-friendly text for severity levels, often used in tags.
export const SeverityTags: { [key: string]: string } = {
  CRITICAL: "Critical",
  HIGH: "High",
  MEDIUM: "Medium",
  LOW: "Low",
  INFORMATIONAL: "Info",
  NONE: "None",
  UNKNOWN: "Unknown",
};

// You can also add a function to get a color safely if needed elsewhere
export const getSeverityColor = (severity?: string): string => {
  if (!severity) return SeverityColors.DEFAULT;
  const upperSeverity = severity.toUpperCase();
  return SeverityColors[upperSeverity] || SeverityColors.UNKNOWN;
};

export const getSeverityTagText = (severity?: string): string => {
  if (!severity) return SeverityTags.UNKNOWN; // Or an empty string or 'N/A'
  const upperSeverity = severity.toUpperCase();
  return SeverityTags[upperSeverity] || severity; // Fallback to the original severity string if no tag is defined
};
