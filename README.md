# SecurityScorer  
  
SecurityScorer is a command-line tool used in [BIECO](https://www.google.com/search?client=safari&rls=en&q=bieco&ie=UTF-8&oe=UTF-8) methodology.

Its purpose is to parse and process the output of other tools that are responsible for the threat evaluation and analysis and some additional user input, specific for each tool. Based on this information, it uses an appropriate inner module for a given tool to calculate a numerical value - a security score.

![securityScorerArchitecture](Images/SecurityScorer_architecture.png?raw=true)

### How to use as CLI
At the moment, SecurityScorer works only for a GraphWalker output and requires some additional user input. Exemplary files can be found in this repository. To run using these files, type:

`python security_scorer.py -m mapping_json_file -r results_xml_file`

for example:

`python security_scorer.py -m mapping.json -r TEST-GraphWalker-20210831T230909449.xml`

## How to use in browser
Create a new virtualenv:

```python3 -m venv /path/to/new/virtual/environment```

Activate the virtualenv:

```source /path/to/new/virtual/environment/bin/activate```

Install the requirements:

```pip install -r requirements.txt```

Run the server:

```uvicorn main:app --reload```

Note: you have to upload mapping file and results file before requesting risk evaluation. Only `graphwalker` module 
is supported at the moment. 