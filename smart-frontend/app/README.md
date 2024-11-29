# ADH/SSM

## Start dev environment

```bash
cd %project_name%/smart-frontend/app
yarn install
yarn start
```

### License 

Please use this command to add license information to your files, in project root folder
```bash
mvn com.mycila:license-maven-plugin:format -DskipTests
```

### Generate SmartRule Lexer and Parser
download `Complete ANTLR Java binaries jar` tool from https://www.antlr.org
generate Lexer, Parser and Listener

```
java -jar ./antlr{VERSION}-complete.jar -Dlanguage=TypeScript SmartRule.g4
```

copy Lexer, Parser and Listener into `utils\smartRule` folder
