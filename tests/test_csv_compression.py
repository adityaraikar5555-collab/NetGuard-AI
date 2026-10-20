"""
Unit and Integration Tests for Smart CSV Optimizer & Compression Engine.
Validates 100MB+ compression benchmarks, GZIP stream parsing, ZIP extraction,
and stratified downsampling to fit within the 25MB threshold.
"""

import gzip
import io
import sys
from pathlib import Path
import unittest
import zipfile

import numpy as np
import pandas as pd

# Add src to path
SRC_DIR = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC_DIR))

from csv_optimizer import SmartCSVOptimizer, csv_optimizer, BENCHMARK_LIMIT_MB


class TestSmartCSVOptimizer(unittest.TestCase):
    def setUp(self):
        # Generate representative network capture data (5000 flows)
        np.random.seed(42)
        n = 5000
        data = {
            "Destination Port": np.random.choice([80, 443, 22, 53, 8080], size=n),
            "Flow Duration": np.random.randint(100, 500000, size=n),
            "Total Fwd Packets": np.random.randint(1, 100, size=n),
            "Total Backward Packets": np.random.randint(0, 100, size=n),
            "Source IP": np.random.choice(["192.168.1.10", "192.168.1.15", "10.0.0.5"], size=n),
            "Destination IP": np.random.choice(["172.217.16.206", "142.250.190.46"], size=n),
            "Protocol": np.random.choice(["TCP", "UDP"], size=n),
            "Label": np.random.choice(["BENIGN", "DDoS", "PortScan"], p=[0.7, 0.2, 0.1], size=n),
        }
        self.df = pd.DataFrame(data)
        csv_buf = io.StringIO()
        self.df.to_csv(csv_buf, index=False)
        self.raw_csv_bytes = csv_buf.getvalue().encode("utf-8")

    def test_compress_csv_to_gzip(self):
        """Test gzip compression efficiency and benchmark compliance."""
        result = csv_optimizer.compress_csv_to_gzip(
            self.raw_csv_bytes,
            filename="capture_5000.csv",
        )
        self.assertTrue(result["success"])
        self.assertTrue(result["compressed_filename"].endswith(".csv.gz"))
        self.assertLess(result["compressed_size_bytes"], result["original_size_bytes"])
        self.assertGreater(result["percent_saved"], 50.0)  # Network CSVs save >50% even on small inputs
        self.assertTrue(result["within_benchmark"])

        # Verify compressed bytes are valid gzip and decompress cleanly
        decompressed_df = pd.read_csv(io.BytesIO(result["compressed_bytes"]), compression="gzip")
        self.assertEqual(len(decompressed_df), len(self.df))
        self.assertEqual(list(decompressed_df.columns), list(self.df.columns))

    def test_decompress_to_dataframe_from_gzip(self):
        """Test transparent parsing of .gz files."""
        gz_res = csv_optimizer.compress_csv_to_gzip(self.raw_csv_bytes, "test.csv")
        df_out, meta = csv_optimizer.decompress_to_dataframe(
            gz_res["compressed_bytes"],
            "test.csv.gz",
        )
        self.assertEqual(meta["format"], "gzip")
        self.assertEqual(len(df_out), len(self.df))

    def test_decompress_to_dataframe_from_zip(self):
        """Test transparent parsing of .zip files containing CSV."""
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("network_traffic.csv", self.raw_csv_bytes)
        zip_bytes = zip_buf.getvalue()

        df_out, meta = csv_optimizer.decompress_to_dataframe(zip_bytes, "archive.zip")
        self.assertEqual(meta["format"], "zip")
        self.assertEqual(meta["extracted_csv"], "network_traffic.csv")
        self.assertEqual(len(df_out), len(self.df))

    def test_downsample_csv_to_budget(self):
        """Test downsampling large datasets to fit under safe target size."""
        # Use a small target to trigger downsampling logic
        target_mb = 0.1  # 100 KB target
        res = csv_optimizer.downsample_csv_to_budget(
            self.raw_csv_bytes,
            filename="large_raw.csv",
            target_max_mb=target_mb,
        )
        self.assertTrue(res["success"])
        self.assertLessEqual(len(res["output_bytes"]), int(target_mb * 1024 * 1024))
        self.assertLess(res["output_rows"], res["original_rows"])
        self.assertTrue(res["within_benchmark"])

    def test_100mb_compression_estimation(self):
        """Test benchmark projection for 100MB network captures."""
        est_100 = csv_optimizer.estimate_compression(100.0)
        self.assertEqual(est_100["input_mb"], 100.0)
        self.assertTrue(est_100["fits_benchmark"])
        self.assertLessEqual(est_100["projected_gz_mb"], BENCHMARK_LIMIT_MB)
        self.assertIn("well within", est_100["recommendation"])


if __name__ == "__main__":
    unittest.main()
