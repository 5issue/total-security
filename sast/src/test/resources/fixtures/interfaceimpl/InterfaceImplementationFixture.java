package fixtures.interfaceimpl;

import java.sql.Statement;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

interface DirectPort {
    String process(String input);
}

class DirectImplementation implements DirectPort {
    public String process(String input) {
        return input;
    }
}

class DirectCaller {
    DirectPort port;

    String call(String input) {
        return port.process(input);
    }
}

class ParameterCaller {
    String call(DirectPort port, String input) {
        return port.process(input);
    }
}

class UnresolvedSameNameCaller {
    String call(Object candidate, String input) {
        if (candidate instanceof DirectPort DirectPort) {
            return DirectPort.process(input);
        }
        return input;
    }
}

interface StaticStylePort {
    static void process(Object input) {}
}

class StaticStyleImplementation implements StaticStylePort {
    Statement statement;

    public void process(String input) throws Exception {
        statement.executeQuery(input);
    }
}

@RestController
class StaticStyleController {
    void run(@RequestParam String input) {
        StaticStylePort.process(input);
    }
}

interface ParentPort {
    String process(String input);
}

interface ChildPort extends ParentPort {}

class ChildImplementation implements ChildPort {
    public String process(String input) {
        return input;
    }
}

class ParentCaller {
    ParentPort port;

    String call(String input) {
        return port.process(input);
    }
}

interface MultiplePort {
    String process(String input);
}

class MultipleA implements MultiplePort {
    public String process(String input) {
        return input;
    }
}

class MultipleB implements MultiplePort {
    public String process(String input) {
        return input;
    }
}

class MultipleCaller {
    MultiplePort port;

    String call(String input) {
        return port.process(input);
    }
}

interface AbstractPort {
    String process(String input);
}

abstract class AbstractBase implements AbstractPort {
    public abstract String process(String input);
}

class RealImplementation extends AbstractBase {
    public String process(String input) {
        return input;
    }
}

class AbstractCaller {
    AbstractPort port;

    String call(String input) {
        return port.process(input);
    }
}

interface MissingPort {
    String process(String input);
}

class MissingCaller {
    MissingPort port;

    String call(String input) {
        return port.process(input);
    }
}

interface AnnotationOnlyPort {
    String process(String input);
}

@Service
class AnnotatedButUnrelated {
    String process(String input) {
        return input;
    }
}

class AnnotationOnlyCaller {
    AnnotationOnlyPort port;

    String call(String input) {
        return port.process(input);
    }
}

class Entity {}

@Repository
interface RuntimeProxyRepository extends JpaRepository<Entity, Long> {}

class RuntimeProxyCaller {
    RuntimeProxyRepository repository;

    Object call(Long id) {
        return repository.findById(id);
    }
}

interface ProjectRepository {
    void search(String input);
}

interface ProjectJpaRepository extends JpaRepository<Entity, Long> {
    Object search(String input);
}

@Repository
class ProjectRepositoryImplementation implements ProjectRepository {
    ProjectJpaRepository jpaRepository;

    public void search(String input) {
        jpaRepository.search(input);
    }
}

class ProjectRepositoryCaller {
    ProjectRepository repository;

    void call(String input) {
        repository.search(input);
    }
}

interface OverloadPort {
    String route(String input);
}

class OverloadImplementation implements OverloadPort {
    public String route(String input) {
        return input;
    }

    public String route(int input) {
        return "safe";
    }
}

class OverloadCaller {
    OverloadPort port;

    String call(String input) {
        return port.route(input);
    }
}

interface BodylessPort {
    String process(String input);
}

class BodylessImplementation implements BodylessPort {
    public native String process(String input);
}

class BodylessCaller {
    BodylessPort port;

    String call(String input) {
        return port.process(input);
    }
}

interface CyclePort {
    void process(String input);
}

class CycleImplementation implements CyclePort {
    CycleCaller caller;

    public void process(String input) {
        caller.call(input);
    }
}

class CycleCaller {
    CyclePort port;

    void call(String input) {
        port.process(input);
    }
}

class ConcreteService {
    String process(String input) {
        return input;
    }
}

class ConcreteCaller {
    ConcreteService service;

    String call(String input) {
        return service.process(input);
    }
}

class DuplicateImplementationCaller {
    DuplicatePort port;

    String call(String input) {
        return port.process(input);
    }
}

class DuplicateInterfaceImplementation
        implements fixtures.interfaceimpl.duplicateport.AmbiguousOwnerPort {
    public String process(String input) {
        return input;
    }
}

class DuplicateInterfaceCaller {
    fixtures.interfaceimpl.duplicateport.AmbiguousOwnerPort port;

    String call(String input) {
        return port.process(input);
    }
}

interface SearchService {
    void search(String query) throws Exception;
}

@Service
class SearchServiceImplementation implements SearchService {
    SearchRepository repository;

    public void search(String query) throws Exception {
        repository.search(query);
    }
}

interface SearchRepository {
    void search(String query) throws Exception;
}

@Repository
class SearchRepositoryImplementation implements SearchRepository {
    Statement statement;

    public void search(String query) throws Exception {
        statement.executeQuery(query);
    }
}

@RestController
class SearchController {
    SearchService service;

    void search(@RequestParam String query) throws Exception {
        service.search(query);
    }
}

interface AmbiguousSearchService {
    void search(String query) throws Exception;
}

class AmbiguousSearchServiceA implements AmbiguousSearchService {
    Statement statement;

    public void search(String query) throws Exception {
        statement.executeQuery(query);
    }
}

class AmbiguousSearchServiceB implements AmbiguousSearchService {
    Statement statement;

    public void search(String query) throws Exception {
        statement.executeQuery(query);
    }
}

@RestController
class AmbiguousSearchController {
    AmbiguousSearchService service;

    void search(@RequestParam String query) throws Exception {
        service.search(query);
    }
}
