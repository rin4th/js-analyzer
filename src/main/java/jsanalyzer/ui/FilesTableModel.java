package jsanalyzer.ui;

import jsanalyzer.store.JsFile;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/** Table model backing the list of JavaScript files. */
public final class FilesTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = {
            "URL", "Status", "Size", "EP", "Secrets", "Ajax", "XSS", "Funcs", "Hits", "Time"
    };

    private List<JsFile> files = new ArrayList<>();

    public void setFiles(List<JsFile> next) {
        files = new ArrayList<>(next);
        fireTableDataChanged();
    }

    public JsFile get(int row) {
        return files.get(row);
    }

    public int indexOf(String key) {
        for (int i = 0; i < files.size(); i++) {
            if (files.get(i).key.equals(key)) {
                return i;
            }
        }
        return -1;
    }

    @Override
    public int getRowCount() {
        return files.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMNS.length;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMNS[column];
    }

    @Override
    public Class<?> getColumnClass(int column) {
        switch (column) {
            case 2:
            case 4:
            case 5:
            case 6:
            case 7:
            case 8:
            case 9:
                return String.class;
            case 3:
                return Integer.class;
            default:
                return String.class;
        }
    }

    @Override
    public Object getValueAt(int row, int column) {
        JsFile file = files.get(row);
        switch (column) {
            case 0:
                return file.url;
            case 1:
                return file.status;
            case 2:
                return formatSize(file.size);
            case 3:
                return file.result == null ? "" : String.valueOf(file.endpointCount());
            case 4:
                return file.result == null ? "" : String.valueOf(file.secretCount());
            case 5:
                return file.result == null ? "" : String.valueOf(file.ajaxCount());
            case 6:
                return file.result == null ? "" : String.valueOf(file.domXssCount());
            case 7:
                return file.result == null ? "" : String.valueOf(file.functionCount());
            case 8:
                return String.valueOf(file.hits);
            case 9:
                return file.result == null ? "" : file.result.durationMs + " ms";
            default:
                return "";
        }
    }

    public static String formatSize(int bytes) {
        if (bytes <= 0) {
            return "0 B";
        }
        String[] units = {"B", "KB", "MB", "GB"};
        double value = bytes;
        int unit = 0;
        while (value >= 1024 && unit < units.length - 1) {
            value /= 1024;
            unit++;
        }
        return (unit == 0 || value >= 10 ? String.format("%.0f", value) : String.format("%.1f", value))
                + " " + units[unit];
    }
}
