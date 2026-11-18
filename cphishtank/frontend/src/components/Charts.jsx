import { useMemo } from "react";
import { ArcElement, BarElement, CategoryScale, Chart as ChartJS, Legend, LinearScale, Tooltip } from "chart.js";
import { Bar, Doughnut } from "react-chartjs-2";
import { useTheme } from "../theme";

ChartJS.register(ArcElement, BarElement, CategoryScale, LinearScale, Tooltip, Legend);
ChartJS.defaults.font.family = "'Inter', system-ui, sans-serif";

const LAB = ["legitimate", "suspicious", "phishing"];

function useChartTheme() {
  const { theme } = useTheme();
  return useMemo(() => theme === "dark" ? {
    colors: { legitimate: "#5bd6a0", suspicious: "#ffd067", phishing: "#ff8791" },
    text: "#b0b6ca", grid: "rgba(176,182,202,.13)", border: "#151724", primary: "#a99cff",
  } : {
    colors: { legitimate: "#16794c", suspicious: "#8a5700", phishing: "#b42332" },
    text: "#586078", grid: "rgba(88,96,120,.12)", border: "#ffffff", primary: "#302878",
  }, [theme]);
}

function axisOptions(palette) {
  return {
    ticks: { color: palette.text },
    grid: { color: palette.grid },
    border: { color: palette.grid },
  };
}

export function LabelDonut({ labels }) {
  const palette = useChartTheme();
  const total = LAB.reduce((a, k) => a + (labels[k] || 0), 0);
  if (!total) return <p className="muted">No scans yet.</p>;
  return <Doughnut aria-label="Scans by verdict" data={{ labels: ["Safe", "Little problem", "Dangerous"],
    datasets: [{ data: LAB.map((k) => labels[k] || 0), backgroundColor: LAB.map((k) => palette.colors[k]), borderWidth: 2, borderColor: palette.border }] }}
    options={{ cutout: "68%", plugins: { legend: { position: "bottom", labels: { color: palette.text, usePointStyle: true, padding: 18 } } } }} />;
}

export function DailyBars({ daily }) {
  const palette = useChartTheme();
  if (!daily.length) return <p className="muted">Nothing scanned in this period.</p>;
  return <Bar aria-label="Scans per day" data={{ labels: daily.map((d) => d.date.slice(5)),
    datasets: LAB.map((k) => ({ label: k === "legitimate" ? "Safe" : k === "suspicious" ? "Little problem" : "Dangerous",
      data: daily.map((d) => d[k]), backgroundColor: palette.colors[k], borderRadius: 4 })) }}
    options={{ scales: { x: { ...axisOptions(palette), stacked: true, grid: { display: false } },
      y: { ...axisOptions(palette), stacked: true, beginAtZero: true, ticks: { color: palette.text, precision: 0 } } },
      plugins: { legend: { position: "bottom", labels: { color: palette.text, usePointStyle: true } } } }} />;
}

export function HBars({ items, label = "count", color }) {
  const palette = useChartTheme();
  if (!items.length) return <p className="muted">Nothing to show yet.</p>;
  return <Bar data={{ labels: items.map((i) => (i.title || i.domain).slice(0, 38)),
    datasets: [{ label, data: items.map((i) => i.count), backgroundColor: color || palette.primary, borderRadius: 4 }] }}
    options={{ indexAxis: "y", plugins: { legend: { display: false } },
      scales: { x: { ...axisOptions(palette), beginAtZero: true, ticks: { color: palette.text, precision: 0 } },
        y: { ...axisOptions(palette), grid: { display: false } } } }} />;
}

export function Columns({ labels, data, color, name = "Responses" }) {
  const palette = useChartTheme();
  return <Bar data={{ labels, datasets: [{ label: name, data, backgroundColor: color || palette.primary, borderRadius: 4 }] }}
    options={{ plugins: { legend: { display: false } },
      scales: { x: { ...axisOptions(palette), grid: { display: false } },
        y: { ...axisOptions(palette), beginAtZero: true, ticks: { color: palette.text, precision: 0 } } } }} />;
}
