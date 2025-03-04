@0xa34652cd31532d4f;

interface Metrics {
    struct TrafficInfos {
        inner @0 :List(TrafficInfo);
    }

    struct TrafficInfo {
        ip @0 :List(UInt8);
        tx @1 :UInt64;
        rx @2 :UInt64;
    }

    getTrafficInfos @0 () -> (reply: TrafficInfos);
}
