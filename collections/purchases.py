class Purchase(object):
    def __init__(
        self, hash_='', number_=0, date_={'timestamp': 0, 'date_string': ''},
        image_id_='', image_url_='', reason_='', location_='', section_='',
        submitted_on_={'timestamp': 0, 'date_string': ''}, submitted_by_='',
        local_nonce_=0, global_nonce_=0
         ):
        self.hash = hash_
        self.number = number_
        self.date = date_ # When it happened. Should be a map of unix epoch to EAT timezone string
        self.image_id = image_id_
        self.image_url = image_url_
        self.reason = reason_
        self.location = location_
        self.section = section_
        self.submitted_on = submitted_on_ # When was submitted. Also map of unix epoch to EAT timezone string
        self.submitted_by = submitted_by_
        self.local_nonce = local_nonce_ # number of this entry in collection, starts with 0
        self.global_nonce = global_nonce_ # number of this entry in whole database, starts with 0 

    @staticmethod
    def from_dict(source):
        pass

    def to_dict(self):
        pass

    def __repr__(self):
        return(
            f'DeadSick(\
                hash={self.hash} \
                number={self.number} \
                date={self.date} \
                image_id={self.image_id} \
                image_url={self.image_url} \
                reason={self.reason} \
                location={self.location} \
                section={self.section} \
                submitted_on={self.submitted_on} \
                submitted_by={self.submitted_by} \
                local_nonce={self.local_nonce} \
                global_nonce={self.global_nonce} \
            )'
        )