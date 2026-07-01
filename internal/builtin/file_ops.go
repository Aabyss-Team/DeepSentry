package builtin

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"ai-edr/internal/executor"
)

func FileDownload(rt Runtime, remotePath, localPath string, chunkSize int) (string, error) {
	if executor.Current == nil {
		return "", fmt.Errorf("执行器未初始化")
	}
	if remotePath == "" || localPath == "" {
		return "", fmt.Errorf("remote_path 和 local_path 必填")
	}
	if chunkSize <= 0 {
		chunkSize = 4 << 20
	}
	out, err := executor.Current.Run("download " + shellQuote(remotePath) + " " + shellQuote(localPath))
	logPath := writeToolExecLog("file_download", fmt.Sprintf("%s -> %s chunk=%d", remotePath, localPath, chunkSize), out, err)
	return formatTransferResult(rt, "下载", remotePath, localPath, chunkSize, logPath, out, err), err
}

func FileUpload(rt Runtime, localPath, remotePath string, chunkSize int) (string, error) {
	if executor.Current == nil {
		return "", fmt.Errorf("执行器未初始化")
	}
	if localPath == "" || remotePath == "" {
		return "", fmt.Errorf("local_path 和 remote_path 必填")
	}
	if chunkSize <= 0 {
		chunkSize = 4 << 20
	}
	out, err := executor.Current.Run("upload " + shellQuote(localPath) + " " + shellQuote(remotePath))
	logPath := writeToolExecLog("file_upload", fmt.Sprintf("%s -> %s chunk=%d", localPath, remotePath, chunkSize), out, err)
	return formatTransferResult(rt, "上传", localPath, remotePath, chunkSize, logPath, out, err), err
}

func ArchivePack(rt Runtime, format, source, dest string) (string, error) {
	format = normalizeArchiveFormat(format, dest)
	if source == "" || dest == "" {
		return "", fmt.Errorf("source 和 dest 必填")
	}
	var out string
	var err error
	if executor.Current != nil && executor.Current.IsRemote() {
		cmd, cerr := archivePackCommand(format, source, dest)
		if cerr != nil {
			return "", cerr
		}
		out, err = executor.Current.Run(cmd)
	} else {
		err = packLocalArchive(format, source, dest)
		if err == nil {
			out = "本地打包完成"
		}
	}
	logPath := writeToolExecLog("archive_pack", fmt.Sprintf("format=%s source=%s dest=%s", format, source, dest), out, err)
	return archiveResult(rt, "打包", format, source, dest, logPath, out, err), err
}

func ArchiveExtract(rt Runtime, format, source, dest string) (string, error) {
	format = normalizeArchiveFormat(format, source)
	if source == "" || dest == "" {
		return "", fmt.Errorf("source 和 dest 必填")
	}
	var out string
	var err error
	if executor.Current != nil && executor.Current.IsRemote() {
		cmd, cerr := archiveExtractCommand(format, source, dest)
		if cerr != nil {
			return "", cerr
		}
		out, err = executor.Current.Run(cmd)
	} else {
		err = extractLocalArchive(format, source, dest)
		if err == nil {
			out = "本地解压完成"
		}
	}
	logPath := writeToolExecLog("archive_extract", fmt.Sprintf("format=%s source=%s dest=%s", format, source, dest), out, err)
	return archiveResult(rt, "解压", format, source, dest, logPath, out, err), err
}

func formatTransferResult(rt Runtime, op, src, dst string, chunk int, logPath, out string, err error) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%s 文件%s\n%s -> %s\nchunk_size=%d\n", rt.tag(), op, src, dst, chunk))
	if logPath != "" {
		b.WriteString("执行日志: " + logPath + "\n")
	}
	if err != nil {
		b.WriteString("状态: 失败: " + err.Error() + "\n")
	} else {
		b.WriteString("状态: 完成\n")
	}
	b.WriteString("\n输出:\n" + out)
	return b.String()
}

func normalizeArchiveFormat(format, path string) string {
	format = strings.ToLower(strings.TrimSpace(format))
	if format != "" {
		return format
	}
	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz"):
		return "tar.gz"
	case strings.HasSuffix(lower, ".tar"):
		return "tar"
	case strings.HasSuffix(lower, ".zip"):
		return "zip"
	case strings.HasSuffix(lower, ".rar"):
		return "rar"
	case strings.HasSuffix(lower, ".7z"):
		return "7z"
	default:
		return "tar.gz"
	}
}

func archivePackCommand(format, source, dest string) (string, error) {
	switch format {
	case "tar.gz", "tgz":
		return fmt.Sprintf("tar -czf %s -C %s %s", shellQuote(dest), shellQuote(filepath.Dir(source)), shellQuote(filepath.Base(source))), nil
	case "tar":
		return fmt.Sprintf("tar -cf %s -C %s %s", shellQuote(dest), shellQuote(filepath.Dir(source)), shellQuote(filepath.Base(source))), nil
	case "zip":
		return fmt.Sprintf("cd %s && zip -r %s %s", shellQuote(filepath.Dir(source)), shellQuote(dest), shellQuote(filepath.Base(source))), nil
	case "7z":
		return fmt.Sprintf("7z a %s %s", shellQuote(dest), shellQuote(source)), nil
	case "rar":
		return fmt.Sprintf("rar a %s %s", shellQuote(dest), shellQuote(source)), nil
	default:
		return "", fmt.Errorf("不支持的打包格式: %s", format)
	}
}

func archiveExtractCommand(format, source, dest string) (string, error) {
	mkdir := "mkdir -p " + shellQuote(dest) + " && "
	switch format {
	case "tar.gz", "tgz":
		return mkdir + fmt.Sprintf("tar -xzf %s -C %s", shellQuote(source), shellQuote(dest)), nil
	case "tar":
		return mkdir + fmt.Sprintf("tar -xf %s -C %s", shellQuote(source), shellQuote(dest)), nil
	case "zip":
		return mkdir + fmt.Sprintf("unzip -o %s -d %s", shellQuote(source), shellQuote(dest)), nil
	case "7z":
		return mkdir + fmt.Sprintf("7z x -y %s -o%s", shellQuote(source), shellQuote(dest)), nil
	case "rar":
		return mkdir + fmt.Sprintf("unrar x -o+ %s %s", shellQuote(source), shellQuote(dest)), nil
	default:
		return "", fmt.Errorf("不支持的解压格式: %s", format)
	}
}

func packLocalArchive(format, source, dest string) error {
	switch format {
	case "tar.gz", "tgz":
		return packTarGz(source, dest)
	case "tar":
		return packTar(source, dest)
	case "zip":
		return packZip(source, dest)
	default:
		return fmt.Errorf("本地纯 Go 暂只支持 zip/tar/tar.gz；%s 需要目标系统安装 7z/rar", format)
	}
}

func extractLocalArchive(format, source, dest string) error {
	switch format {
	case "tar.gz", "tgz":
		return extractTar(source, dest, true)
	case "tar":
		return extractTar(source, dest, false)
	case "zip":
		return extractZip(source, dest)
	default:
		return fmt.Errorf("本地纯 Go 暂只支持 zip/tar/tar.gz；%s 需要目标系统安装 7z/unrar", format)
	}
}

func archiveResult(rt Runtime, op, format, source, dest, logPath, out string, err error) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%s 归档%s format=%s\n%s -> %s\n", rt.tag(), op, format, source, dest))
	if logPath != "" {
		b.WriteString("执行日志: " + logPath + "\n")
	}
	if err != nil {
		b.WriteString("状态: 失败: " + err.Error() + "\n")
	} else {
		b.WriteString("状态: 完成\n")
	}
	if strings.TrimSpace(out) != "" {
		b.WriteString("\n输出:\n" + out)
	}
	return b.String()
}

func packZip(source, dest string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return err
	}
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()
	zw := zip.NewWriter(out)
	defer zw.Close()
	base := filepath.Dir(source)
	return filepath.Walk(source, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(base, path)
		w, err := zw.Create(rel)
		if err != nil {
			return err
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		_, err = io.Copy(w, in)
		return err
	})
}

func packTar(source, dest string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return err
	}
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()
	tw := tar.NewWriter(out)
	defer tw.Close()
	return writeTar(source, filepath.Dir(source), tw)
}

func packTarGz(source, dest string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return err
	}
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()
	gw := gzip.NewWriter(out)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()
	return writeTar(source, filepath.Dir(source), tw)
}

func writeTar(source, base string, tw *tar.Writer) error {
	return filepath.Walk(source, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(base, path)
		h, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		h.Name = rel
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		_, err = io.Copy(tw, in)
		return err
	})
}

func extractZip(source, dest string) error {
	r, err := zip.OpenReader(source)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, f := range r.File {
		target := filepath.Join(dest, f.Name)
		if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(dest)+string(os.PathSeparator)) {
			return fmt.Errorf("非法 zip 路径: %s", f.Name)
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		in, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.Create(target)
		if err != nil {
			in.Close()
			return err
		}
		_, err = io.Copy(out, in)
		in.Close()
		out.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func extractTar(source, dest string, gz bool) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	var r io.Reader = in
	if gz {
		gr, err := gzip.NewReader(in)
		if err != nil {
			return err
		}
		defer gr.Close()
		r = gr
	}
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		target := filepath.Join(dest, h.Name)
		if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(dest)+string(os.PathSeparator)) {
			return fmt.Errorf("非法 tar 路径: %s", h.Name)
		}
		if h.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		out, err := os.Create(target)
		if err != nil {
			return err
		}
		_, err = io.Copy(out, tr)
		out.Close()
		if err != nil {
			return err
		}
	}
}
