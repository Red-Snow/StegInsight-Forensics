export interface AnalysisResult {
  fileType: string;
  fileSize: number;
  fileName: string;
  likelihood: number; // 0 to 100
  findings: Finding[];
  metadata: Record<string, any>;
  suggestions: string[];
}

export interface Finding {
  type: 'critical' | 'warning' | 'info';
  message: string;
  details?: string;
}

export interface LsbData {
  plane: number;
  canvas: HTMLCanvasElement;
}
