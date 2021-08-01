package embedded;

import java.util.TimerTask;

public class CollectStats extends TimerTask {


    int count = 1;

    public void run() {
        //System.out.println(count+" : Test");
        //count++;
        SDCLoader.send_stats();  // Send collected stats to server every 1 minute
    }
}

