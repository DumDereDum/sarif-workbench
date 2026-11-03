/** Returns the next project baseline when a run's baseline button is clicked. */
export function toggleBaselineSelection(
  currentBaselineRunId: string | null,
  clickedRunId: string,
): string | null {
  return currentBaselineRunId === clickedRunId ? null : clickedRunId
}
