<?php
namespace Flownative\OpenIdConnect\Client\Command;

use Doctrine\Common\Persistence\ObjectManager as DoctrineObjectManager;
use Doctrine\ORM\EntityManager as DoctrineEntityManager;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Exception\GuzzleException;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Cli\CommandController;

final class OidcCommandController extends CommandController
{
    /**
     * @var DoctrineEntityManager
     */
    protected $entityManager;

    /**
     * @Flow\InjectConfiguration
     * @var array
     */
    protected $settings;

    /**
     * @param DoctrineObjectManager $entityManager
     * @return void
     */
    public function injectEntityManager(DoctrineObjectManager $entityManager): void
    {
        $this->entityManager = $entityManager;
    }

    /**
     * Discover
     *
     * @param string $serviceName
     * @return void
     */
    public function discoverCommand(string $serviceName): void
    {
        if (!isset($this->settings['services'][$serviceName])) {
            $this->outputLine('<error>Unknown service "%s".</error>', [$serviceName]);
            exit(1);
        }
        if (!isset($this->settings['services'][$serviceName]['options']['discoveryUri'])) {
            $this->outputLine('<error>Missing option "discoveryUri" for service "%s".</error>', [$serviceName]);
            exit(1);
        }

        $httpClient = new HttpClient();

        try {
            $response = $httpClient->request('GET', $this->settings['services'][$serviceName]['options']['discoveryUri']);
        } catch (GuzzleException $e) {
            $this->outputLine('<error>Failed discovering options at %s: %s</error>', [$this->settings['services']['options'][$serviceName]['discoveryUri'], $e->getMessage()]);
            exit(1);
        }

        $discoveredOptions = \GuzzleHttp\json_decode($response->getBody()->getContents(), true);
        if (!is_array($discoveredOptions)) {
            $this->outputLine('<error>Discovery endpoint returned invalid response</error>');
            exit(1);
        }

        $rows = [];
        foreach ($discoveredOptions as $optionName => $optionValue) {
            $rows[] = [
                $optionName,
                !is_string($optionValue) ? var_export($optionValue, true) : $optionValue
            ];
        }

        $this->output->outputTable($rows, ['Option', 'Value']);
    }
}
