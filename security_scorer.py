import getopt
import json
import sys
import xml.etree.ElementTree as ET


def auto_str(cls):
    def __str__(self):
        return '%s(\n%s)\n' % (
            type(self).__name__,
            ',\n '.join('\n%s=%s' % item for item in vars(self).items())
        )
    cls.__str__ = __str__
    return cls


class Mapping:
    def __init__(self, mapping_name, mapping_version, threats, model_to_threat_mapping):
        self.mapping_name = mapping_name
        self.mapping_version = mapping_version
        self.threats = threats
        self.model_to_threat_mapping = model_to_threat_mapping


class ThreatGeneral:
    def __init__(self, name, impact):
        self.name = name
        self.impact = impact

    def __str__(self):
        return f'Threat: {self.name}, impact: {self.impact}'

    def __eq__(self, other):
        return self.name == other.name

    def __lt__(self, other):
        return self.name < other.name

    def __hash__(self):
        return hash(self.name + str(self.impact))


class ThreatInMapping:
    def __init__(self, name, weight):
        self.name = name
        self.weight = weight

    def __str__(self):
        return f'Threat: {self.name}, weight: {self.weight}'

    def __eq__(self, other):
        return self.name == other.name and self.weight == other.weight

    def __lt__(self, other):
        return self.name < other.name

    def __hash__(self):
        return hash(self.name + str(self.weight))


class ThreatCombined:
    def __init__(self, name, weight, impact):
        self.name = name
        self.weight = weight
        self.impact = impact

    def __str__(self):
        return f'Threat: {self.name}, weight: {self.weight}, impact: {self.impact}'

    def __hash__(self):
        return hash(self.name + str(self.weight) + str(self.impact))


class TestToThreatMapping:
    def __init__(self, model_name, threats):
        self.test_name = model_name
        self.threats = threats

    def __str__(self):
        return f"TestToThreatMapping: {self.test_name}, threats: {' '.join(str(x) for x in self.threats)}"


def parse_threats_general(threat_dic):
    threats_list = set()
    for threat in threat_dic:
        threats_list.add(ThreatGeneral(threat['name'], threat['impact']))
    return sorted(threats_list)


def parse_threats_in_mapping(threat_dic):
    threats_list = set()
    for threat in threat_dic:
        threats_list.add(ThreatInMapping(threat['name'], threat['weight']))
    return sorted(threats_list)


def parse_model_to_threats_mapping(mapping_dic):
    model_to_threats_mapping_list = []
    for model_to_threats_mapping in mapping_dic:
        model_to_threats_mapping_list.append(
            TestToThreatMapping(
                model_to_threats_mapping['test_name'],
                parse_threats_in_mapping(model_to_threats_mapping['threats'])
            )
        )
    return model_to_threats_mapping_list


def get_set_of_all_threats_in_mapping(model_to_threats_mapping_list):
    threats = set()
    for mapping in model_to_threats_mapping_list:
        for threat in mapping.threats:
            threats.add(threat)
    return sorted(threats)


def get_list_of_all_threats_in_mapping(model_to_threats_mapping_list):
    threats = list()
    for mapping in model_to_threats_mapping_list:
        for threat in mapping.threats:
            threats.append(threat)
    return sorted(threats)

# reads a mapping from file
def read_mapping(filename):
    f = open(filename, "r")
    dic = json.loads(f.read())
    # print(dic, sep="\n")

    mapping_name = dic['name']
    mapping_version = dic['version']

    threats_set = parse_threats_general(dic['threats'])

    model_to_threats_mapping_list = parse_model_to_threats_mapping(dic['test_to_threats_mapping'])

    # verify that threats set provided by user is the same as the set of all threats in mapping
    if threats_set != get_set_of_all_threats_in_mapping(model_to_threats_mapping_list):
        print("\tWarning! A set of threats provided by user is different than the set of all threats in mapping!")
    else:
        print("\tInput data is consistent: a set of threats provided by user and a set of threats existing in the "
              "mapping itself are equal.")

    return mapping_name, mapping_version, threats_set, model_to_threats_mapping_list


class Result:
    def __init__(self, test_name, failures, errors):
        self.test_name = test_name
        self.failures = failures
        self.errors = errors

    def __str__(self):
        return f'Result: {self.test_name}, failures: {self.failures}, errors: {self.errors}'


def read_results(filename):
    root = ET.parse(filename).getroot()
    results = []
    for type_tag in root.findall('testsuite/testcase'):
        test_name = type_tag.get('name')
        failures = []
        errors = []
        for child in type_tag:
            if child.tag == "failure":
                failures.append(child.attrib)
            elif child.tag == "error":
                errors.append(child.attrib)
        results.append(Result(test_name, failures, errors))
    return results


def print_usage():
    print ("Usage: python threat_evaluator -m mapping_json_file -r results_xmi_file")


def parse_arguments():
    MAPPING_FILE_PATH = ""
    RESULTS_FILE_PATH = ""
    full_cmd_arguments = sys.argv
    argument_list = full_cmd_arguments[1:]
    short_options = "hm:r:"
    long_options = ["help", "mapping=", "results="]
    try:
        arguments, values = getopt.getopt(argument_list, short_options, long_options)
    except getopt.error as err:
        # Output error, and return with an error code
        print (str(err))
        print_usage()
        sys.exit(2)
    for current_argument, current_value in arguments:
        if current_argument in ("-h", "--help"):
            print_usage()
        elif current_argument in ("-r", "--results"):
            RESULTS_FILE_PATH = current_value
        elif current_argument in ("-m", "--mapping"):
            MAPPING_FILE_PATH = current_value

    if RESULTS_FILE_PATH == "" or MAPPING_FILE_PATH == "":
        print_usage()
        sys.exit(2)

    return MAPPING_FILE_PATH, RESULTS_FILE_PATH


class FinalResult:
    def __init__(self, test_name, threats, failures, errors):
        self.test_name = test_name
        self.threats = threats
        self.failures = failures
        self.errors = errors
        self.value = calculate_value(threats, failures, errors)

    def __str__(self):
        return "FinalResult: " + self.test_name + ", threats: " + ' '.join(str(x) for x in self.threats) \
               + ", failures: " + ' '.join(str(x) for x in self.failures) + ", errors: " \
               + ' '.join(str(x) for x in self.errors) + ", value: " + str(self.value)


def create_final_results(model_to_threats_mapping, threats_general, results):
    final_results = []

    for mapping in model_to_threats_mapping:
        found_results = list(filter(lambda result : result.test_name == mapping.test_name, results))
        if len(found_results) > 1:
            print("ERROR! More than two test cases in results matching a single test case in mapping: " +
                  mapping.test_name + "!")
        elif len(found_results) == 0:
            print("ERROR! No test case in results matches a test case in model: " + mapping.test_name + "!")
        else:
            threats_combined = []
            for threat_mapping in mapping.threats:
                found_general_threats = list(filter(lambda t: t.name == threat_mapping.name, threats_general))
                if len(found_general_threats) == 0:
                    print("ERROR! No threat on general threat list matches a given test from mapping.")
                elif len(found_general_threats) > 1:
                    print("ERROR! More than 1 threat on general threat list matches a given test from mapping.")
                else:
                    threats_combined.append(ThreatCombined(
                        threat_mapping.name, threat_mapping.weight, found_general_threats[0].impact))

            final_results.append(
                FinalResult(
                    mapping.test_name,
                    threats_combined,
                    found_results[0].failures,
                    found_results[0].errors
                )
            )

    return final_results


def calculate_value(threats, failures, errors):
    value = 0
    if len(errors) > 0 or len(failures) > 0:
        pass
    else:
        value += sum([threat.impact * threat.weight for threat in threats]) / sum([threat.impact for threat in threats])

    return value

if __name__ == '__main__':
    mapping_file_path, results_file_path = parse_arguments()

    print("""  ___                  _ _        ___                     
 / __| ___ __ _  _ _ _(_) |_ _  _/ __| __ ___ _ _ ___ _ _ 
 \__ \/ -_) _| || | '_| |  _| || \__ \/ _/ _ \ '_/ -_) '_|
 |___/\___\__|\_,_|_| |_|\__|\_, |___/\__\___/_| \___|_|  
                             |__/                         """)

    print("\nParsing mapping file...")
    name, version, threats_list, model_to_threats_mapping = read_mapping(mapping_file_path)
    print("\tname: " + name + "\n\tversion: " + version)
    print("\tList of threats existing in this mapping:")
    for threat in threats_list:
        print("\t\t"+ str(threat))

    print("\tMapping:")
    for mapping in model_to_threats_mapping:
        print("\t\t" + mapping.test_name + ": " + str([threat.name + ", weight: " + str(threat.weight) for
                                                       threat in mapping.threats]))
    print("Done parsing mapping file.")

    print("\nParsing results file...")
    results = read_results(results_file_path)
    print("\tResults:")
    for result in results:
        print("\t\t" + str(result))

    print("Done parsing results file.")

    print("\nCalculating final results...")
    final_results = create_final_results(model_to_threats_mapping, threats_list, results)
    sumarized_value = sum([result.value for result in final_results])

    print("Done calculating final results.")
    print("\n**************************\nCalculated value is: " + str(sumarized_value) + "\n**************************")



