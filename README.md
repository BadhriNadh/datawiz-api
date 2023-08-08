# datawiz
<h3> Project's User Scenarios:</h3>
<i>The following showcases the general workflows the user performs using our application:</i>
<ul>
<li>User can sign up.</li>
<li>User can sign in after they have signed up, or if they have an existing account.</li>
<li>User can add a database connection configuration from the "Config Database" page.</li>
<li>While adding a dashboard configuration, the user can test whether they can connect to that database using the supplied credentials.</li>
<li>User can also test the connection of an existing database configuration once they have saved it.</li>
<li>User can delete an existing database connection configuration from the "Config Database" page.</li>
<li>User can edit an existing database connection configuration in that page, and test its connection again.</li>
<li>User can then click on an existing database connection to access that database's visualizations page, where user can create, edit, or delete that database's visualizations.</li>
<li>When creating a visualization, the user:</li><ol>
<li>Provides a name for the visualization.</li>
<li>Chooses one of the database's schemas.</li>
<li>Chooses the visualization's chart type (bar, line, pie).</li>
<li>Selects a table from that schema to be the x-table.</li>
<li>Select an attribute from x-table to be mapped to the x-axis.</li>
<li>Selects a table from that schema to be the y-table.</li>
<li>Select an attribute from x-table to be mapped to the y-axis. However, the y-axis attribute an only be integer, float, or double.</li>
<li>Chooses an aggregate calculation to be performed (sum, count, avg), but this is only applicable when the x-axis's data has more than one data point. </li>
<li>Before saving the visualization, the user can preview it by clicking the "preview" button.</li>
<li>The user can then save the visualization, which will redirect them to the database's visualizations page (where the new visualization is displayed).</li>
</ol></ul><ul>
<li> User can edit an existing visualization where they can modify its name, schema, x-table, x-attribute, y-table, and y-attribute.</li>
<li> In this visualization edit page, the visualization's data is displayed in tabular format alongside the generated graph.</li>
<li> User can delete an existing visualization from the database's visualization page.</li>
<li> A database's visualization page displays that database's existing visualization in a paginated format, where each page contains up to six of that database's visualizations. </li>
<li> User can create multiple custom dashboards to house up to four of their existing visualizations so that they may compare them side-by-side. This can be done by clicking the "add" button on the custom dashboard page, where they would provide a name for this custom dashboard then save it to create it. </li>
<li> The all custom dashboards page displays to the user all their existing dashboards in a paginated format, where each page contains up to six of their existing dashboards. </li>
<li> In this all custom dashboards page, users can delete any of their existing dashboards. </li>
<li> The user can click on one of their custom dashboards from this page, which will redirect them to that custom dashboard. </li>
<li> Inside a custom dashboard, the user can edit the dashboard's name. </li>
<li> Inside a custom dashboard, the user can add visualization by selecting a schema which will display the visualizations that are associated with that schema (only schemas that have at least one visualization will be shown to the user as options). The user can then choose one of these visualizations and it will be added to their custom dashboard. </li>
<li> Note that users can choose visualizations from different schemas as well as from the same schema in a single custom dashboard. </li>
<li> Inside a custom dashboard, the user can click the "refresh" button at the top that will refresh the data of all the visualizations in that dashboard (i.e., update all visualizations by fetching their data).</li>
<li> Inside a custom dashboard, the user can delete visualizations from the custom dashboard. </li>
<li> User can log out by choosing "logout" from the drop-down at the top right of the page. </li>
</ul>

<h3>Back-End Dependencies: </h3>
<i>The pom.xml file included in the back-end (datawiz-api) folder contains all the back-end's
necessary external dependencies. So, running the pom file (through some like mvn compile or mvn build)
should install and configure the dependencies, which include the following libraries:</i>

<ul>
<li>Spring Boot JDBC</li>
<li>Spring Boot Data JPA</li>
<li>Spring Boot Data JDBC</li>
<li>Spring Boot OAuth2 Resource Server</li>
<li>Spring Boot Starter Web</li></Li>
<li>MySQL Connector J</li>
<li>Spring Boot Configuration Processor</li>
<li>Spring Boot Starter Test</li>
<li>MySQL Connector Java</li>
</ul>
<u>Note that this project's back-end uses Java Version 17. </u>

<h3> Back-End Build Instructions/Commands:</h3>

<h3>Front-End Dependencies:</h3>
<ul>
<li>The front-end is developed using <b>React.JS</b></li>
<li>Node version <b>v18.13.0</b></li>
<li>Use yarn for the project with yarn version <b>1.22.4</b></li>
<li>The dependencies are mentioned inside the <b>package.json</b> file inside the Front-End folder</li>
<li>To install all the dependencies execute <b>yarn</b> command</li>
<li>To start the project run <b>yarn dev</b> command</li>
<li>To refactor the code <b>ESLint</b> is used</li>
</ul>

<h3>CI/CD stages for Front-End:</h3>
<i>Build Stage</i>
<ul>
<li>First I have used docker image of node with the version <b>v18.13.0</b></li>
<li>Now as the project requirement if to use <b>yarn</b> but this image doesnot have yarn</li>
<li>So, to install all the dependencies execute <b>npx yarn</b> command</li>
<li>And finally to create build folder run <b>npx yarn build</b> command</li>
</ul>

<i>Deploy Stage</i>
<ul>
<li>First I have used docker image of node with the version <b>v18.13.0</b></li>
<li>Now as the project requirement if to use <b>yarn</b> but this image doesnot have yarn</li>
<li>So, to install all the dependencies execute <b>npx yarn</b> command</li>
<li>Now, to create build folder run <b>npx yarn build</b> command</li>
<li>Then ssh key for the vm has been stored in the varibale with the name <b>FRONTEND_PRIVATE_KEY</b></li>
<li>Once, the build folder is created, then it is pushed onto the VM using scp command</li>
</ul>

<h3>Front-End Build Instructions/Commands: </h3>
<ul>
<li>To deploy the front-end we first need to create the build folder</li>
<li>To create build folder <b>yarn build</b> command is used</li>
</ul>
