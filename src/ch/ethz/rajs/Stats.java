package ch.ethz.rajs;

public class Stats {
    public static void logConst(Object o) {
        if(o instanceof Integer) {
            System.out.println("STATS_CONST_INT=" + o);
        } else if (o instanceof String) {
            System.out.println("STATS_CONST_STRING=" + o.toString());
        } else if (o instanceof Long) {
            System.out.println("STATS_CONST_LONG=" + o);
        } else if (o instanceof Float) {
            System.out.println("STATS_CONST_FLOAT=" + o);
        } else if (o instanceof Double) {
            System.out.println("STATS_CONST_DOUBLE=" + o);
        } else {
            System.err.println("STATS_ERR=Ignoring unknown constant: " + o);
        }
    }
}
