import time

class QueuedItem(object):
    def __init__(self, item):
        self.time_added = time.time()
        self.item = item

    @property
    def age(self):
        return time.time() - self.time_added

    def __repr__(self):
        return f"{self.item}[{self.age}]"



class SimpleTemporalQueue(object):
    def __init__(self, queue_len=16, unique=False, name="", timeout=10):
        self.queue = []   # list of QuedItems
        self.max_queue_length = queue_len
        self.uniq = unique
        self.name = name
        self.timeout = timeout
        self.DEBUG =  False  # only hold first telegram in queue

    def put(self, item):
        index = len(self)
        q_item = QueuedItem(item)
        if self.DEBUG:
            if len(self.queue) > 0:
                return False
        self.maintenance()
        if len(self.queue) < self.max_queue_length:
            if self.uniq and item not in self.queue:
                self.queue.append(q_item)
                return True
            elif not self.uniq:
                self.queue.append(q_item)
                return True
        return False

    def maintenance(self):
        # clean out any old queue entries
        for item in self.queue:
            if item.age > self.timeout:
                self.queue.remove(item)

    def get(self):
        # get next item off queue, FIFO style
        if self.queue:
            if self.DEBUG:
                # dont pop it, just return it
                return self.queue[0].item
            q_item =self.queue.pop(0)
            return q_item.item

    @property
    def empty(self):
        return self.__len__ == 0

    def __len__(self):
        return len(self.queue)

    def __str__(self):
        return f"Q|{self.name}:({self.max_queue_length}){self.queue}"