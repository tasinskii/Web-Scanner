import json
import sys
from datetime import datetime

import pandas as pd
import texttable as tt

# prep data
def load_prepare_data(file_path):
    with open(file_path) as file:
        raw_data = json.load(file)
    dataframe = pd.DataFrame(raw_data).transpose()
    dataframe[['min_rtt', 'max_rtt']] = pd.DataFrame(dataframe['rtt_range'].apply(lambda x: x if isinstance(x, list) else [None, None]).tolist(), index=dataframe.index)
    return dataframe

# table gen
class UnifiedTableGenerator:
    def __init__(self, data):
        self.data = data

    def create_table(self, part):
        if part == 1:
            return self.domain_info_table()
        elif part == 2:
            return self.rtt_info_table()
        elif part == 3:
            return self.ca_count_table()
        elif part == 4:
            return self.server_count_table()
        elif part == 5:
            return self.security_features_table()

    def domain_info_table(self):
        table = self.init_table()
        columns = ["Domain Name", "Scan Time", "IPv4", "IPv6", "Server", "Insecure HTTP", "Redirect to HTTPS", "HSTS", "TLS", "Root CA", "RDNS Names", "Min. RTT", "Max. RTT", "Locations"]
        self.set_table_header(table, columns)

        for index, row in self.data.iterrows():
            row_data = [index, datetime.utcfromtimestamp(row['scan_time']).strftime('%Y-%m-%d %H:%M:%S')]
            fields = ['ipv4_addresses', 'ipv6_addresses', 'http_server', 'insecure_http', 'redirect_to_https', 'hsts', 'tls_versions', 'root_ca', 'rdns_names', 'min_rtt', 'max_rtt', 'geo_locations']
            for field in fields:
                row_data.append(self.format_field(row, field))
            table.add_row(row_data)
        return table

    def rtt_info_table(self):
        table = self.init_table()
        columns = ["Domain Name", "Minimum RTT", "Maximum RTT"]
        self.set_table_header(table, columns)

        sorted_data = self.data.sort_values(by=['min_rtt'])
        for index, row in sorted_data.iterrows():
            table.add_row([index, row['min_rtt'], row['max_rtt']])
        return table

    def ca_count_table(self):
        table = self.init_table()
        columns = ["Root Certificate Authority", "Count"]
        self.set_table_header(table, columns)

        ca_count = self.data.groupby(['root_ca']).size().reset_index(name='count').sort_values(by=['count'], ascending=False)
        for _, row in ca_count.iterrows():
            table.add_row([row['root_ca'], row['count']])
        return table

    def server_count_table(self):
        table = self.init_table()
        columns = ["Web Server", "Count"]
        self.set_table_header(table, columns)

        server_count = self.data.groupby(['http_server']).size().reset_index(name='count').sort_values(by=['count'], ascending=False)
        for _, row in server_count.iterrows():
            table.add_row([row['http_server'], row['count']])
        return table

    def security_features_table(self):
        table = self.init_table()
        columns = ['TLSv1.0', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3', 'SSLv2', 'SSLv3', 'Insecure HTTP', 'Redirect to HTTPS', 'HSTS', 'IPv6 Enabled']
        self.set_table_header(table, columns, width=10)

        df = self.data
        # Ensuring each feature is evaluated correctly
        for version in ['TLSv1.0', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3', 'SSLv2', 'SSLv3']:
            df[version] = df['tls_versions'].apply(lambda tls: version in tls if tls is not None else False)
        
        df['Insecure HTTP'] = df['insecure_http'].apply(lambda x: x is True)
        df['Redirect to HTTPS'] = df['redirect_to_https'].apply(lambda x: x is True)
        df['HSTS'] = df['hsts'].apply(lambda x: x is True)
        df['IPv6 Enabled'] = df['ipv6_addresses'].apply(lambda x: x is not None and len(x) > 0)

        # Calculate the percentage for each security feature
        percentages = []
        for feature in columns:
            percentage = (df[feature].sum() / len(df)) * 100
            percentages.append(f"{percentage:.2f} %")

        table.add_row(percentages)

        return table



    def init_table(self):
        table = tt.Texttable(max_width=0)
        table.set_deco(tt.Texttable.HEADER | tt.Texttable.BORDER | tt.Texttable.HLINES | tt.Texttable.VLINES)
        return table


    def set_table_header(self, table, columns, width=20):
        table.set_cols_align(['c'] * len(columns))
        table.set_cols_width([width] * len(columns))
        table.header(columns)

    def format_field(self, row, field):
        if isinstance(row[field], bool):
            return 'YES' if row[field] else 'NO'
        elif isinstance(row[field], list):
            return '\n'.join(row[field])
        else:
            return str(row[field])

def main():
    input_file_path = sys.argv[1]
    output_file_path = sys.argv[2]
    data = load_prepare_data(input_file_path)

    table_generator = UnifiedTableGenerator(data)

    parts = [1, 2, 3, 4, 5]
    tables = [table_generator.create_table(part) for part in parts]

    content = "\n\n".join([table.draw() for table in tables])

    write_to_file(content, output_file_path)

def write_to_file(content, file_path):
    with open(file_path, "w") as file:
        file.write(content)

if __name__ == "__main__":
    main()

