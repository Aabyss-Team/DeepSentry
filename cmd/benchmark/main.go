package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"ai-edr/internal/benchmark"
	"ai-edr/internal/tui"
	"ai-edr/internal/ui"
)

func main() {
	cfgPath := flag.String("c", "/tmp/deepsentry-smoke.yaml", "配置文件路径")
	outDir := flag.String("o", "reports/benchmark", "报告输出目录")
	skipLLM := flag.Bool("skip-llm", false, "跳过 LLM 相关场景")
	skipRemote := flag.Bool("skip-remote", false, "跳过远程/SSH 场景")
	benchTUI := flag.Bool("tui", false, "TUI 可视化报告")
	flag.Parse()

	if len(flag.Args()) > 0 {
		*cfgPath = flag.Args()[0]
	}

	if *benchTUI {
		if err := tui.RunBenchmark(*cfgPath, *skipLLM, *skipRemote); err != nil {
			fmt.Fprintf(os.Stderr, "%s%v\n", ui.Prefix("❌", "[ERR]"), err)
			os.Exit(1)
		}
		return
	}

	fmt.Println(ui.Prefix("🚀", "[RUN]") + "DeepSentry Agent Benchmark 启动...")
	report, err := benchmark.RunSuite(*cfgPath, *skipLLM, *skipRemote)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s%v\n", ui.Prefix("❌", "[ERR]"), err)
		os.Exit(1)
	}

	benchmark.PrintSummary(report)

	jsonPath, mdPath, err := benchmark.WriteReports(report, *outDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s报告写入失败: %v\n", ui.Prefix("⚠️", "[WARN]"), err)
	} else {
		abs, _ := filepath.Abs(mdPath)
		fmt.Printf("\n%s报告已保存:\n   JSON: %s\n   MD:   %s\n", ui.Prefix("📊", "[STAT]"), jsonPath, abs)
	}

	if report.OverallScore < 60 {
		os.Exit(1)
	}
}
