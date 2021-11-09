# SecurityScorer  
  
SecurityScorer is a command-line tool used in [BIECO](https://www.google.com/search?client=safari&rls=en&q=bieco&ie=UTF-8&oe=UTF-8) methodology.

Its purpose is to parse and process the output of other tools that are responsible for the threat evaluation and analysis and some additional user input, specific for each tool. Based on this information, it uses an appropriate inner module for a given tool to calculate a numerical value - a security score.

![securityScorerArchitecture](Images/SecurityScorer_architecture.png?raw=true)

### How to use
At the moment, SecurityScorer works only for a GraphWalker output and requires some additional user input. Exemplary files can be found in this repository. To run using these files, type:

`python security_scorer.py -m mapping_json_file -r results_xml_file`

for example:

`python security_scorer.py -m mapping.json -r TEST-GraphWalker-20210831T230909449.xml`