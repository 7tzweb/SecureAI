import { ResultsClient } from "@/components/results/results-client";

export default async function ScanPage({
  params,
}: {
  params: Promise<{ scanId: string }>;
}) {
  const { scanId } = await params;

  return (
    <ResultsClient scanId={scanId} />
  );
}
