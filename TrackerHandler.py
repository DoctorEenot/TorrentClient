import time
import threading



def handler(torrent):
    
    while True:
        threads_pool = []
        for tracker_index in range(len(torrent.trackers)):
            if torrent.trackers[tracker_index].working:
                if time.time() - torrent.trackers[tracker_index].last_announce >= torrent.trackers[tracker_index].interval:
                    new_thread = threading.Thread(target=torrent.trackers[tracker_index].announce,args=(torrent,))
                    threads_pool.append(new_thread)
                    threads_pool[len(threads_pool)-1].start()
        for thread in threads_pool:
            thread.join()

